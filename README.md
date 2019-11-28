# OpenID Connect Provider for Nodejs _(@interop-alliance/oidc-op)_

[![Build Status](https://travis-ci.org/interop-alliance/oidc-op.svg?branch=master)](https://travis-ci.org/interop-alliance/oidc-op)
[![npm version](https://badge.fury.io/js/%40interop-alliance%2Foidc-op.svg)](https://badge.fury.io/js/%40interop-alliance%2Foidc-op)

> Embeddable OpenID Connect Provider for Nodejs

This library aims to implement a minimal OpenID Connect Provider for
Nodejs. It is not intended to be used directly by most developers, but rather
via a complete self-contained server such as 
[Life Server](https://github.com/interop-alliance/life-server). 
Some applications require an embedded identity provider, such as entertainment 
or IoT appliances. This package can be used directly in these cases.

The module should make available an OIDCProvider class which can be
instantiated multiple times to support multitenancy use cases. It should also
have a method that provides a mountable router or app for widely used frameworks
like Express.

## Table of Contents

* [Security](#security)
* [Background](#background)
* [Install](#install)
* [Develop](#develop)
* [Maintainers](#maintainers)
* [Contribute](#contribute)
* [MIT License](#mit-license)

## Security

...

## Background

### Internal Interface

OpenID Connect makes no provisions for how a user is initially authenticated
by the IdP. It's up to the implementer to determine whether to use passwords,
LDAP, SAML, OAuth, or some other means. The host system is responsible for
other dependencies of the OIDC authentication flows as well, such as
persistence, managing user attributes, multi-factor auth and so on.

In addition to implementing OpenID Connect Provider functions, this library
defines an interface between OpenID Connect and the host application.

The goal of the interface is to manage the flow of responsibility between the
OpenID Connect implementation and functions provided by the host application,
such as local user authentication, persistence, and domain specific event
handing.

## Install

```bash
$ npm install @interop-alliance/oidc-op --save
```

## Develop

### Test

```bash
npm test
```

## Maintainers

* Dmitri Zagidulin

## Contribute

### Style guide

* ES6
* Standard JavaScript
* jsdocs

### Code of conduct

* @interop-alliance/oidc-op follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.

## MIT License

[The MIT License](LICENSE.md)

Copyright (c) 2016 [Anvil Research, Inc.](http://anvil.io)<br/>
Copyright (c) 2017-2019 Dmitri Zagidulin and The Solid Project
