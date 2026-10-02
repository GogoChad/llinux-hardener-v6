from hardener.models import CheckResult
from hardener.utils import command_output


def check_docker_socket():
    exists = bool(command_output(["bash", "-lc", "command -v docker"]))
    if not exists:
        return CheckResult("DOCKER-001", "Docker available", "docker", "info", "SKIP", "Docker is not installed", tags=["docker"])
    containers = command_output(["docker", "ps", "--format", "{{.Names}}"])
    count = len([x for x in containers.splitlines() if x.strip()])
    return CheckResult("DOCKER-001", "Review running containers", "docker", "medium", "PASS",
                       f"{count} running container(s)", count, False, ["docker", "plugin"])


def register():
    return {"DOCKER-001": check_docker_socket}
