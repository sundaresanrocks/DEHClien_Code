from metric_handler import MetricHandler
import docker
import dockermap

class ManageContainer(MetricHandler):
    def __init__(self, docker_ca_cert, docker_client_cert, docker_client_key, https_url):
        super().__init__(docker_ca_cert, docker_client_cert, docker_client_key, https_url)
        self.tls_config = docker.tls.TLSConfig(ca_cert=self.docker_ca_cert,
                                               client_cert=(self.docker_client_cert,
                                                            self.docker_client_key))

        self.__docker_client = docker.DockerClient(base_url=self.https_url,
                                                   tls=self.tls_config,
                                                   timeout=self.DOCKER_CLIENT_TIMEOUT)