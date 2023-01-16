"""
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import subprocess
import sys
import time

from fabric.api import cd, run

sys.path.append('../../../../../orc8r')
import tools.fab.dev_utils as dev_utils
from tools.fab.hosts import vagrant_setup
from tools.fab.python_utils import strtobool

magma_path = "../../../../../"
orc8_docker_path = magma_path + "orc8r/cloud/docker/"
agw_path = magma_path + "lte/gateway/"
feg_path = magma_path + "feg/gateway/"
feg_docker_path = feg_path + "docker/"
feg_docker_integ_test_path = agw_path + "python/integ_tests/federated_tests/docker/"
agw_vagrant_path = "magma/lte/gateway/"
feg_docker_integ_test_path_vagrant = agw_vagrant_path + "python/integ_tests/federated_tests/docker/"
feg_vagrant_path = "magma/feg/gateway/"
orc8r_vagrant_path = "magma/orc8r/cloud/docker/"

vagrant_agw_path = "~/lte/gateway"


def build_all_and_configure(clear_orc8r='False', provision_vm='False'):
    """
    Build, start and configure AGW, FEG and Orc8r
    Args:
        clear_orc8r: removes all contents from orc8r database like gw configs
        provision_vm: forces the re-provision of the magma VM
    """
    build_all(clear_orc8r, provision_vm)
    start_all()
    configure_orc8r()


def build_all(clear_orc8r='False', provision_vm='False', orc8r_on_vagrant='False'):
    """
    Build AGW, FEG and Orc8r
    Args:
        clear_orc8r: removes all contents from orc8r database like gw configs
        provision_vm: forces the reprovision of the magma VM
    """
    # build all components
    build_orc8r(on_vagrant=orc8r_on_vagrant)
    print("#### Starting Orc8r (to generate certificates) ####")
    # need to start orc8r to generate certificates
    start_orc8r(on_vagrant=orc8r_on_vagrant)
    build_feg()
    build_agw(provision_vm=provision_vm)

    if strtobool(clear_orc8r):
        clear_orc8r_db()

    # build other VMs
    build_test_vm(provision_vm=provision_vm)
    build_magma_trf(provision_vm=provision_vm)


def build_orc8r(on_vagrant='False'):
    """
    Build orc8r locally on the host VM
    """
    on_vagrant = strtobool(on_vagrant)
    command = './build.py -a'
    if not on_vagrant:
        subprocess.check_call(command, shell=True, cwd=orc8_docker_path)
    else:
        vagrant_setup('magma', destroy_vm=False)
        with cd(orc8r_vagrant_path):
            run(command)


def start_orc8r(on_vagrant='False'):
    """
    Start orc8r locally on Docker
    """
    on_vagrant = strtobool(on_vagrant)
    command = './run.py'
    if not on_vagrant:
        subprocess.check_call(command, shell=True, cwd=orc8_docker_path)
    else:
        vagrant_setup('magma', destroy_vm=False)
        with cd(orc8r_vagrant_path):
            run(command)


def configure_orc8r(on_vagrant='False'):
    """
    Configure orc8r with a federated AGW and FEG
    """
    on_vagrant = strtobool(on_vagrant)
    print('#### Configuring orc8r ####')
    command_agw = 'fab --fabfile=dev_tools.py register_federated_vm'
    command_feg = 'fab register_feg_gw'
    if not on_vagrant:
        subprocess.check_call(command_agw, shell=True, cwd=agw_path)
        subprocess.check_call(command_feg, shell=True, cwd=feg_path)
    else:
        vagrant_setup('magma', destroy_vm=False)
        with cd(agw_vagrant_path):
            run(command_agw)
        with cd(feg_vagrant_path):
            run(command_feg)


def clear_orc8r_db():
    """
    Delete orc8r database. Requires orc8r to be stopped
    """
    print('#### Clearing swagger database from Orc8r ####')
    subprocess.check_call(['./run.py --clear-db'], shell=True, cwd=orc8_docker_path)
    print(
        '#### Remember you may need to delete '
        'gateway certs from the AGW and FEG ####',
    )


def build_agw(provision_vm='False'):
    """
    Build magma on AGW on magma Vagrant VM

       provision_vm: forces the reprovision of the magma VM
    """
    print('#### Building AGW ####')
    subprocess.check_call(
        'fab build_and_start_magma:provision_vm=%s'
        % provision_vm, shell=True, cwd=agw_path,
    )


def start_agw(provision_vm='False'):
    """
    start AGW on Vagrant VM
    """
    subprocess.check_call(
        'fab start_magma:provision_vm=%s' % provision_vm,
        shell=True, cwd=agw_path,
    )


def build_feg():
    """
    build FEG on magma Vagrant vm using docker running in Vagrant
    """
    print('#### Building FEG on Magma Vagrant VM ####')
    vagrant_setup('magma', destroy_vm=False)

    with cd(feg_docker_integ_test_path_vagrant):
        run('docker-compose down')
        run('docker-compose build')
        run('./run.py')


def start_feg():
    """
    start FEG on magma Vagrant vm using docker running in Vagrant
    """
    vagrant_setup('magma', destroy_vm=False)
    with cd(feg_docker_integ_test_path_vagrant):
        run('./run.py')


def build_test_vm(provision_vm='False'):
    print('#### Building test vm ####')
    subprocess.check_call('vagrant up magma_test', shell=True, cwd=agw_path)
    subprocess.check_call(
        'fab make_integ_tests:provision_vm=%s'
        % provision_vm, shell=True, cwd=agw_path,
    )


def build_magma_trf(provision_vm='False'):
    print('#### Building Traffic vm ####')
    subprocess.check_call('vagrant up magma_trfserver', shell=True, cwd=agw_path)
    subprocess.check_call(
        'fab build_and_start_magma_trf:provision_vm=%s'
        % provision_vm, shell=True, cwd=agw_path,
    )


def start_all(provision_vm='False', orc8r_on_vagrant='False'):
    """
    start AGW, FEG and Orc8r
    Args:
        provision_vm: forces the provision of the magma VM
    """
    start_orc8r(on_vagrant=orc8r_on_vagrant)
    start_agw(provision_vm)
    start_feg()


def test_connectivity(timeout=10):
    """
    Check if all running gateways have connectivity
    Args:
        timeout: amount of time the command will retry
    """
    # check AGW-Cloud connectivity
    print("### Checking AGW-Cloud connectivity ###")
    subprocess.check_call(
        f'fab --fabfile=dev_tools.py '
        f'check_agw_cloud_connectivity:timeout={timeout}',
        shell=True, cwd=agw_path,
    )

    # check FEG-cloud connectivity
    print("\n### Checking FEG-Cloud connectivity ###")
    vagrant_setup('magma', destroy_vm=False)
    with cd(feg_docker_integ_test_path_vagrant):
        dev_utils.run_remote_command_with_repetition(
            'docker-compose exec magmad checkin_cli.py', timeout,
        )

    # check AGW-FEG connectivity
    print("\n### Checking AGW-FEG connectivity ###")
    subprocess.check_call(
        f'fab --fabfile=dev_tools.py '
        f'check_agw_feg_connectivity:timeout={timeout}',
        shell=True, cwd=agw_path,
    )
