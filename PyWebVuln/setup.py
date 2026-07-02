from setuptools import setup, find_packages

setup(
    name="PyWebVuln",
    version="1.0.4",
    packages=find_packages(),
    install_requires=[
        "flask>=2.3.0",
        "sqlalchemy>=2.0.0",
        "pycryptodome>=3.19.0",
        "cryptography>=41.0.0",
        "pyjwt>=2.8.0",
        "requests>=2.31.0",
    ],
)
