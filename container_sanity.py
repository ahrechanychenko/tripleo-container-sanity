import commands
import pprint
import unittest, pytest

def get_overcloud_nodes():
    exit_code, output = commands.getstatusoutput(
        'source /home/stack/stackrc '
        + '&& openstack server list -f value -c Networks|awk -F\'=\'  \'{print $2}\'')
    return output.split("\n")

def run_cmd_on_undercloud_node(cmd):
    status, output = commands.getstatusoutput("{}".format(cmd))
    return output


def run_cmd_on_overcloud_nodes(cmd, nodes_list):
    output_dict = {}
    for node in nodes_list:
        sshcmd = "ssh -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no heat-admin@{}".format(node)
        status, output = commands.getstatusoutput("{} {}".format(sshcmd, cmd))
        output_dict[node] = output
    return output_dict


def check_overcloudrc_file():
    output = run_cmd_on_undercloud_node("cat overcloudrc")
    if "No such file or directory" in output:
        return False
    else:
        return True


def get_undercloud_version():
    output = run_cmd_on_undercloud_node("cat /etc/rhosp-release")
    version = output.split()[5].split(".")[0]
    return version


@pytest.mark.overcloud_sanity
class Overcloud_Testing(unittest.TestCase):
    if check_overcloudrc_file():
        @staticmethod
        def test_check_docker_service_is_running_on_overcloud_nodes():
            print"\t Check that docker service is running on overcloud nodes \n"
            nodes = get_overcloud_nodes()
            result = run_cmd_on_overcloud_nodes("sudo systemctl is-active docker", nodes)
            for node in nodes:
                print "status of docker daemon on node {} : {}".format(node, result[node])
                assert "active" == result[node], "\ndocker daemon isn't running on {} node\n".format(node)

        @staticmethod
        def test_check_docker_containers_running_state_on_overcloud_nodes():
            print "\t Check that docker containers have running state on overcloud nodes \n"
            nodes = get_overcloud_nodes()
            docker_containers_names = run_cmd_on_overcloud_nodes(
                '"sudo docker ps -a --format \'table {{.Names}}\'|awk \'{if(NR>1)print}\' | sort"', nodes)
            docker_containers = {}
            for node in nodes:
                docker_containers[node] = {key: None for key in docker_containers_names[node].split('\n')}

            # collecting all necessary data
            for node in nodes:
                for name in docker_containers[node].keys():
                    cmd = '"sudo docker ps -a -f name=%s ' \
                          '--format \'table {{.Status}}\'|awk \'{if(NR>1)print}\' | sort"' % (name)
                    docker_containers[node][name] = run_cmd_on_overcloud_nodes(cmd, [node, ])[node]
            # analyzing data
            try:
                for node in nodes:
                    for name in docker_containers[node].keys():

                        # check exit code if container state == exited
                        if "Exited" in docker_containers[node][name]:
                            assert "Exited (0)" in docker_containers[node][
                                name], "\ndocker container {} didn't exited correctly on {} node\n" \
                                       "".format(
                                name, node)
                        else:
                            if name == "nova_migration_target":
                                assert "Up" in docker_containers[node][
                                    name], "\ndocker container {} isn't running on {} node\n".format(
                                    name, node)
                            else:
                                assert "Up" in docker_containers[node][
                                    name], "\ndocker container {} isn't running on {} node\n".format(
                                    name, node)
                                assert "(unhealthy)" not in docker_containers[node][
                                    name], "\ndocker container {} isn't unhealthy on {} node\n".format(
                                    name, node)
            except AssertionError:
                filtered_dict = {}
                bad_status = ["(unhealthy)", "Exited (1)", "Restarting"]
                for node in docker_containers.keys():
                    for container in docker_containers[node]:
                        if any(word in docker_containers[node][container] for word in bad_status):
                            filtered_dict[node] = {container: docker_containers[node][container]}
                print "List of failed containers on overcloud nodes \n"
                pprint.pprint(filtered_dict)
                raise

        @staticmethod
        def test_check_docker_container_volume():
            print "\t Check that dir for docker containers volumes exist on overcloud nodes \n"
            nodes = get_overcloud_nodes()
            docker_container_volumes = run_cmd_on_overcloud_nodes(
                'sudo ls -l /var/lib/docker/containers', nodes)
            for node in nodes:
                assert "No such file or directory" not in docker_container_volumes[node]

            docker_container_volumes = run_cmd_on_overcloud_nodes(
                'sudo docker volume ls ', nodes)
            for node in nodes:
                assert "local" in docker_container_volumes[node]

        @staticmethod
        def test_check_openstack_services_in_docker_containers():
            print "\t Check that openstack services running in docker containers on overcloud nodes \n"
            nodes = get_overcloud_nodes()
            docker_containers_process = {}
            docker_containers_names = run_cmd_on_overcloud_nodes(
                '"sudo docker ps --format \'table {{.Names}}\'|awk \'{if(NR>1)print}\' | sort"', nodes)
            for node in nodes:
                docker_containers_process[node] = {key: None for key in docker_containers_names[node].split('\n')}
            for node in nodes:
                for name in docker_containers_process[node].keys():
                    if name == "horizon":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "httpd")
                    elif name == "swift_xinetd_rsync":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "xinet")
                    elif name == "neutron_server_tls_proxy":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "httpd")
                    elif name == "glance_api_tls_proxy" or name == "swift_proxy_tls_proxy":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "httpd")
                    elif name == "redis_tls_proxy":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "stunnel")
                    elif "cron" in name:
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "crond")
                    elif name == "swift_rsync":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "rsync")
                    elif name == "nova_migration_target":
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "sshd")
                    elif "openstack-cinder-volume-docker" in name:
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "/usr/bin/cinder-volume")
                    elif name == "clustercheck":
                        cmd = 'sudo docker exec clustercheck clustercheck'
                    else:
                        cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, name[:4])
                    docker_containers_process[node][name] = run_cmd_on_overcloud_nodes(cmd, [node, ])[node]
                    if name == "clustercheck":
                        assert "Galera cluster node is synced." in docker_containers_process[node][name]
                    else:
                        assert "Error response from daemon:" not in docker_containers_process[node][
                            name], "\n cannot connect to container {} on node {}\n".format(name, node)
                        assert len(docker_containers_process[node][name]) != 0, "\n" \
                                                                                "overcloud service {} " \
                                                                                "isn't running inside {} container\n".format(
                            name, node)
    else:
        pass



@pytest.mark.undercloud_sanity
class Undercloud_Testing(unittest.TestCase):
    container_details = {}
    if int(get_undercloud_version()) >= 14:
        container_details['container_operator'] = 'podman'
    else:
        container_details['container_operator'] = 'docker'

    if int(get_undercloud_version()) >= 14:
        @staticmethod
        def test_check_docker_service_is_running_on_undecloud():
            print"\t Check that docker service is running on overcloud nodes \n"
            result = run_cmd_on_undercloud_node("sudo systemctl is-active {}".format())
            print "status of docker daemon on undercloud node: {}".format(result)
            assert "active" == result, "\ndocker daemon isn't running on undercloud node\n"

        @staticmethod
        def test_check_docker_containers_running_state_on_undercloud_node():
            print "\t Check that docker containers have running state on undercloud node \n"
            docker_containers_names = run_cmd_on_undercloud_node("sudo docker ps -a --format \'table {{.Names}}\'|awk \'{if(NR>1)print}\' | sort")
            docker_containers = {key: None for key in docker_containers_names.split('\n')}

            # collecting all necessary data
            for name in docker_containers.keys():
                cmd = "sudo docker ps -a -f name=%s --format \'table {{.Status}}\'|awk \'{if(NR>1)print}\' | sort" % (name)
                docker_containers[name] = run_cmd_on_undercloud_node(cmd)
            # analyzing data
            try:
                for name in docker_containers.keys():

                    # check exit code if container state == exited
                    if "Exited" in docker_containers[name]:
                        assert "Exited (0)" in docker_containers[name], \
                            "\ndocker container {} didn't exited correctly \n".format(name)
                    else:
                        assert "Up" in docker_containers[name], "\ndocker container {} isn't running\n".format(
                            name)
                        assert "(unhealthy)" not in docker_containers[name], \
                            "\ndocker container {} isn't unhealthy ".format(
                            name)
            except AssertionError:
                filtered_dict = {}
                bad_status = ["(unhealthy)", "Exited (1)", "Restarting"]
                for container in docker_containers:
                    if any(word in docker_containers[container] for word in bad_status):
                        filtered_dict = {container: docker_containers[container]}
                print "List of failed containers on overcloud nodes \n"
                pprint.pprint(filtered_dict)
                raise

        @staticmethod
        def test_check_docker_container_volume():
            print "\t Check that dir for docker containers volumes exist on overcloud nodes \n"
            docker_container_volumes = run_cmd_on_undercloud_node(
                'sudo ls -l /var/lib/docker/containers')
            assert "No such file or directory" not in docker_container_volumes
            docker_container_volumes = run_cmd_on_undercloud_node(
                'sudo docker volume ls ')
            assert "local" in docker_container_volumes

        @staticmethod
        def test_check_undercloud_services_in_docker_containers():
            print "\t Check that openstack services running in docker containers on undercloud \n"
            docker_containers_names = run_cmd_on_undercloud_node(
                "sudo docker ps --format \'table {{.Names}}\'|awk \'{if(NR>1)print}\' | sort")
            docker_containers_process = {key: None for key in docker_containers_names.split('\n')}
            for name in docker_containers_process.keys():
                if name == "keystone_cron" or name == "nova_api_cron" or name == "heat_api_cron":
                    cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "crond")
                elif name == "swift_rsync":
                    cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "rsync")
                elif "http" in name or "ui" in name:
                    cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, "httpd")
                else:
                    cmd = 'sudo docker exec %s ps -aux |grep %s|grep -v ps' % (name, name[:4])
                docker_containers_process[name] = run_cmd_on_undercloud_node(cmd)
                assert "Error response from daemon:" not in docker_containers_process[name], \
                    "\n cannot connect to container\n".format(name)
                assert len(docker_containers_process[name]) != 0, "\n" \
                                                                        "undercloud service {0} " \
                                                                        "isn't running inside {0} container\n".format(
                    name)
    else:
        pass