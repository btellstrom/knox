<!--
{% comment %}
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to you under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
{% endcomment %}
-->

## Docker

`src/resources/docker` contains a number of Dockerfiles and Docker-compose
configuration files to launch an Apache Knox server. Maven automation
exists for the base Docker image "apache/knox" which can be invoked with
the "-Pdocker" Maven profile.

## Docker Hub

`src/main/resources/dockerhub` contains a copy of the same `apache/knox` Dockerfile
that is present in `src/main/resources/docker` that is designed to be used with the
automation around publishing Docker images to the Apache Docker Hub account.

It is not expected that users would interact with this Dockerfile.

