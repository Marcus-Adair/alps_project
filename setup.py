from setuptools import setup, find_packages

setup(
    name="alps_project",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "alps_project=alps.main:main",
        ],
    },
)
