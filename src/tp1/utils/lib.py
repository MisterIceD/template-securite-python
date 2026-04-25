from scapy.arch.windows import get_windows_if_list

def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interfaces = get_windows_if_list()

    for index, iface in enumerate(interfaces):
        name = iface.get("name", "Unknown")
        description = iface.get("description", "")
        print(f"{index} - {name} ({description})")

    choice = int(input("Choisis une interface réseau : "))
    return interfaces[choice]["name"]