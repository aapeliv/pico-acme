import setuptools

with open("README.md") as f:
    long_description = f.read()

with open("src/pico_acme/version") as f:
    version = f.read().strip()

setuptools.setup(
    name="pico_acme",
    version=version,
    author="Aapeli Vuorinen",
    description="Pico ACME: tiny ACMEv2 client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aapeliv/pico-acme",
    project_urls={
        "GitHub": "https://github.com/aapeliv/pico-acme",
        "Bug Tracker": "https://github.com/aapeliv/pico-acme/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    package_data={"pico_acme": ["version"]},
    python_requires=">=3.8",
    install_requires=[
        "acme==2.9.0",
        "cryptography>=3.2.1",
        "PyOpenSSL>=17.5.0,!=23.1.0",
        "pyrfc3339",
    ],
)
