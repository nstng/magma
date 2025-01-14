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
from typing import Dict, Tuple

from fabric import Connection
from tools.fab import vagrant


def split_hoststring(hoststring: str) -> Tuple[str, str, str]:
    """
    Splits a host string into its user, hostname, and port components

    e.g. 'vagrant@localhost:22' -> ('vagrant', 'localhost', '22')
    """
    user = hoststring[0:hoststring.find('@')]
    ip = hoststring[hoststring.find('@') + 1:hoststring.find(':')]
    port = hoststring[hoststring.find(':') + 1:]
    return user, ip, port


def vagrant_connection(
    c: Connection, host: str, destroy_vm: bool = False,
    force_provision: bool = False,
) -> Connection:
    conn, _ = vagrant_setup(c, host, destroy_vm, force_provision)
    return conn


def vagrant_setup(
        c: Connection, host: str, destroy_vm: bool = False,
        force_provision: bool = False,
) -> Tuple[Connection, Dict[str, str]]:
    """
    Setup the specified vagrant box

    host: the Vagrant box to setup, e.g. "magma"
    """
    if destroy_vm:
        vagrant.teardown_vagrant(c, host)
    return vagrant.setup_env_vagrant(c, host, force_provision=force_provision)


def ansible_setup(
    hoststr, ansible_group, playbook,
    preburn='false', full_provision='true',
):
    """
    Setup the specified ansible machine

    hoststr: the host string of the target host
             e.g. vagrant@192.168.60.10:22

    ansible_group: The group the deploy targets
             e.g. "dev"

    preburn: 'true' to run preburn tasks, 'false' to skip them.
             Defaults to 'false'

    full_provision: 'true' to run post-preburn tasks, 'false' to skip them.
                    Defaults to 'true'
    """
    # Provision the gateway host
    (user, ip, port) = split_hoststring(hoststr)

    with Connection(host=ip, user=user, port=int(port)) as c:
        c.run(
            "echo '[%s]\nhost ansible_host=%s ansible_user=%s"
            " ansible_port=%s' > /tmp/hosts" % (ansible_group, ip, user, port),
        )
        c.run(
            "ansible-playbook -i /tmp/hosts deploy/%s "
            "--extra-vars '{\"preburn\": %s, \"full_provision\": %s}'" %
            (playbook, preburn, full_provision),
        )
