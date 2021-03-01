from setuptools import setup, find_packages

setup(
    name='jupyterhub-ltiauthenticator',
    version='1.0.0',
    description='JupyterHub authenticator implementing LTI v1.1 / v1.3',
    url='https://github.com/jupyterhub/ltiauthenticator',
    author='Yuvi Panda',
    author_email='yuvipanda@gmail.com',
    license='3 Clause BSD',
    packages=find_packages(),
    python_requires=">=3.5",
    install_requires=[
        'josepy==1.4.0',
        'jupyterhub>=1.3.0',
        'jwcrypto==0.8',
        'oauthlib>=3.0',
        'oauthenticator>=0.13.0',
        'pem==20.1.0',
        'pycryptodome==3.9.8',
        'PyJWT==1.7.1',
        'pyjwkest==1.4.2',
    ]
)
