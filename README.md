# k8s_osquery

Based on the docker tables that have been added to osquery core this was an experimentation around adding functionality to use osquery to collect kubernetes data.

This module is designed to be compiled in to osquery core. It leverages k8s unauthenticated API access that is actively being deprecated.

Entry points have been written for /api/v1/services and /api/v1/pods
