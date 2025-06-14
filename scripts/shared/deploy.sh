#!/usr/bin/env bash

set -em

source "${SCRIPTS_DIR}/lib/utils"
print_env CABLE_DRIVER DEPLOYTOOL OVERLAPPING IMAGE_TAG LIGHTHOUSE PARALLEL PLUGIN PRELOAD_IMAGES SETTINGS TIMEOUT USE_CLUSTERSET_IP
source "${SCRIPTS_DIR}/lib/debug_functions"
source "${SCRIPTS_DIR}/lib/deploy_funcs"

# Source plugin if the path is passed via plugin argument and the file exists
# shellcheck disable=SC1090
[[ -n "${PLUGIN}" ]] && [[ -f "${PLUGIN}" ]] && source "${PLUGIN}"

### Constants ###
# These are used in other scripts
# shellcheck disable=SC2034
readonly CE_IPSEC_IKEPORT=500
# shellcheck disable=SC2034
readonly CE_IPSEC_NATTPORT=4500
# shellcheck disable=SC2034
readonly SUBM_CS="submariner-catalog-source"
# shellcheck disable=SC2034
readonly SUBM_INDEX_IMG="${SUBM_IMAGE_REPO}/submariner-operator-index:${SUBM_IMAGE_TAG}"
# shellcheck disable=SC2034
readonly BROKER_NAMESPACE="submariner-k8s-broker"
# shellcheck disable=SC2034
readonly BROKER_CLIENT_SA="submariner-k8s-broker-client"
readonly MARKETPLACE_NAMESPACE="olm"
IPSEC_PSK="$(dd if=/dev/urandom count=64 bs=8 | LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)"
# shellcheck disable=SC2034
readonly IPSEC_PSK

### Common functions ###

# Create a CatalogSource
# 1st argument is the catalogsource name
# 2nd argument is the namespace
# 3rd argument is index image url
function create_catalog_source() {
  local cs=$1
  local ns=$2
  # shellcheck disable=SC2034 # this variable is used elsewhere
  local iib=$3  # Index Image Build
  echo "[INFO](${cluster}) Create the catalog source ${cs}..."

  kubectl delete catalogsource/operatorhubio-catalog -n "${MARKETPLACE_NAMESPACE}" --wait --ignore-not-found
  kubectl delete catalogsource/"${cs}" -n "${MARKETPLACE_NAMESPACE}" --wait --ignore-not-found

  # Create the CatalogSource
  render_template "${RESOURCES_DIR}"/common/catalogSource.yaml | kubectl apply -f -

  # Wait for the CatalogSource readiness
  if ! with_retries 60 kubectl get catalogsource -n "${MARKETPLACE_NAMESPACE}" "${cs}" -o jsonpath='{.status.connectionState.lastObservedState}'; then
    exit_error "[ERROR](${cluster}) CatalogSource ${cs} is not ready."
  fi

  echo "[INFO](${cluster}) Catalog source ${cs} created"
}

# Create an OperatorGroup
# 1st argument is the operatorgroup name
# 2nd argument is the target namespace
function create_operator_group() {
  local og=$1
  local ns=$2

  echo "[INFO](${cluster}) Create the OperatorGroup ${og}..."
  # Create the OperatorGroup
  render_template "${RESOURCES_DIR}"/common/operatorGroup.yaml | kubectl apply -f -
}

# Install the bundle, subscript and approve.
# 1st argument is the subscription name
# 2nd argument is the target catalogsource name
# 3nd argument is the source namespace
# 4th argument is the bundle name
function install_bundle() {
  local sub=$1
  local cs=$2
  local ns=$3
  local bundle=$4
  local installPlan

  # Delete previous CatalogSource and Subscription
  kubectl delete sub/"${sub}" -n "${ns}" --wait --ignore-not-found

  # Create the Subscription (Approval should be Manual not Automatic in order to pin the bundle version)
  echo "[INFO](${cluster}) Install the bundle ${bundle} ..."
  render_template "${RESOURCES_DIR}"/common/subscription.yaml | kubectl apply -f -

  # Manual Approve
  echo "[INFO](${cluster}) Approve the InstallPlan..."
  kubectl wait --for condition=InstallPlanPending --timeout=5m -n "${ns}" subs/"${sub}" || exit_error "[ERROR](${cluster}) InstallPlan not found."
  installPlan=$(kubectl get subscriptions.operators.coreos.com "${sub}" -n "${ns}" -o jsonpath='{.status.installPlanRef.name}')
  if [ -n "${installPlan}" ]; then
    kubectl patch installplan -n "${ns}" "${installPlan}" -p '{"spec":{"approved":true}}' --type merge
  fi

  echo "[INFO](${cluster}) Bundle ${bundle} installed"
}

function declare_global_cidrs() {
  declare -gA global_CIDRs

  for cluster in "${clusters[@]}"; do
    # shellcheck disable=SC2034
    global_CIDRs[$cluster]="242.254.${cluster_number[$cluster]}.0/24"
  done
}

function declare_clusterset_ip_cidrs() {
  declare -gA clusterset_ip_CIDRs

    for cluster in "${clusters[@]}"; do
      # shellcheck disable=SC2034
      clusterset_ip_CIDRs[$cluster]="243.254.${cluster_number[$cluster]}.0/24"
    done
}

# This is a workaround and can be removed once we switch the CNI from kindnet to a different one.
# In order to support health-check and hostNetwork use-cases, submariner requires an IPaddress from the podCIDR
# for each node in the cluster. Normally, most of the CNIs create a cniInterface on the host and assign an IP
# from the podCIDR to the interface. Submariner relies on this interface to support the aforementioned use-cases.
# However, with kindnet CNI, it was seen that it does not create a dedicated CNI Interface on the nodes.
# But as soon as a pod is scheduled on a node, it creates a veth-xxx interface which has an IPaddress from the
# podCIDR. In this workaround, we are scheduling a dummy pod as a demonSet on the cluster to trigger the creation
# of this veth-xxx interface which can be used as a cniInterface and we can continue to validate Submariner use-cases.
function schedule_dummy_pod() {
    [[ -z "${cluster_cni[$cluster]}" ]] || return 0
    local ns="subm-kindnet-workaround"
    source "${SCRIPTS_DIR}"/lib/deploy_funcs
    import_image "${REPO}/nettest"

    echo "Creating the ${ns} namespace..."
    kubectl create namespace "${ns}" || :
    deploy_resource "${RESOURCES_DIR}"/dummypod.yaml "$ns"
}

function deploy_subm_global_cm() {
    local ns="submariner-operator"
    source "${SCRIPTS_DIR}"/lib/deploy_funcs

    echo "Creating the ${ns} namespace..."
    kubectl create namespace "${ns}" || :
    echo Setting up submariner global configmap...
    NFTABLES="${NFTABLES:-false}"
    deploy_resource "${RESOURCES_DIR}"/sm-global-cm.yaml "$ns"
}


### Main ###

load_settings
declare_cidrs
[[ "$OVERLAPPING" != "true" ]] || declare_global_cidrs
[[ "$USE_CLUSTERSET_IP" != "true" ]] || declare_clusterset_ip_cidrs
declare_kubeconfig

# Always import nettest image on kind, to be able to test connectivity and other things
[[ "${PROVIDER}" != 'kind' ]] || import_image "${REPO}/nettest"

# Always get subctl since we're using moving versions, and having it in the image results in a stale cached one
"${SCRIPTS_DIR}/get-subctl.sh"

load_library deploy DEPLOYTOOL
deploytool_prereqs
[[ "$PROVIDER" != kind ]] || run_all_clusters schedule_dummy_pod
run_all_clusters deploy_subm_global_cm
run_if_defined pre_deploy

with_context "$broker" setup_broker
install_subm_all_clusters

if [ "${#cluster_subm[@]}" -gt 1 ]; then
    # shellcheck disable=2206 # the array keys don't have spaces
    cls=(${!cluster_subm[@]})
    with_context "${cls[0]}" with_retries 30 verify_gw_status
    with_context "${cls[0]}" connectivity_tests "${cls[1]}"
else
    echo "Not executing connectivity tests - requires at least two clusters with submariner installed"
fi

if [ "$DEMO" = true ]; then
    # shellcheck disable=2068 # the array keys don't have spaces
    for context in ${!cluster_subm[@]}; do
        with_context "$context" deploy_demo "$context"
    done
fi

run_if_defined post_deploy

# Print installed versions for manual validation of CI
subctl show versions
print_clusters_message

# If there are any local components, check that the deployed versions are the newly-built versions
# This is known to fail with Helm so ignore that
if [[ -n "$LOCAL_COMPONENTS" && "$DEPLOYTOOL" != helm ]]; then
    for component in $LOCAL_COMPONENTS; do
        for version in $(subctl show versions | awk "/$component/ { print \$4 }"); do
            # shellcheck disable=SC2153 # VERSION is provided externally
            if [ "$version" != "$VERSION" ]; then
                printf "Expected version %s of component %s, but got %s.\n" "$VERSION" "$component" "$version"
                exit 1
            fi
        done
    done
fi
