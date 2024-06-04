from setuptools import find_packages, setup

setup(
    name="etebase_server",
    version="0.13.1",
    description="An Etebase (EteSync 2.0) server",
    url="https://www.etebase.com/",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Framework :: Django",
        "Framework :: FastAPI",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU Affero General Public License v3",
    ],
    packages=find_packages(include=["etebase_server", "etebase_server.*"]),
    install_requires=list(open("requirements.in/base.txt")),
    package_data={
        "etebase_server": ["templates/*"],
    },
)
