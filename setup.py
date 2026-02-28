from setuptools import setup, find_packages

setup(
    name="snxui",
    version="0.1.0",
    packages=find_packages(exclude=["tests*", "packaging*", "docs*"]),
    package_data={
        "snxui.data": ["*.policy", "*.desktop", "icons/*.svg"],
    },
    entry_points={
        "gui_scripts": [
            "snxui = snxui.app:main",
        ],
    },
)
