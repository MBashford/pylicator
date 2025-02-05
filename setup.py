from setuptools import setup

VERSION = "0.1.3"
DESCRIPTION = "A SNMP trap exploder/forwarder implemented in python"
LONG_DESCRIPTION = """
A SNMP trap exploder/forwarder implemented in python. Enables logging received 
traps using python-asn1 to perform a naive decode of the SNMP PUD
"""

setup(
    name="pylicator",
    version=VERSION,
    python_requires='>=3.8',
    author="Milo Bashford",
    author_email="milobashford@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    packages=["pylicator"],
    install_requires=["asn1"],
    package_dir={"": "src"},
    package_data={"pylicator": ["pylicator.service"]}
)