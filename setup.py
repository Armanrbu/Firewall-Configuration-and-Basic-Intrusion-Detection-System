"""
NetGuard IDS — setup.py for optional pip install.
"""

from setuptools import find_packages, setup

setup(
    name="netguard-ids",
    version="1.0.0",
    description="Advanced Firewall & Intrusion Detection System",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Arman",
    url="https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "PySide6>=5.15",
        "psutil>=5.9",
        "requests>=2.28",
        "pyyaml>=6.0",
        "python-dotenv>=1.0",
    ],
    extras_require={
        "full": [
            "PyQtWebEngine>=5.15",
            "scikit-learn>=1.3",
            "joblib>=1.3",
            "schedule>=1.2",
            "plyer>=2.1",
            "flask>=3.0",
            "reportlab>=4.0",
            "matplotlib>=3.7",
            "numpy>=1.24",
        ]
    },
    entry_points={
        "console_scripts": [
            "netguard=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: Security",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
    ],
)
