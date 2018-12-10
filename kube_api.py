#!/usr/bin/env python

import osquery
import os

from datetime import datetime, timezone
from kubernetes import client, config

@osquery.register_plugin
class K8Services(osquery.TablePlugin):
    def name(self):
        return "k8s_services"

    def columns(self):
        return [
            osquery.TableColumn(name="name", type=osquery.STRING),
            osquery.TableColumn(name="type", type=osquery.STRING),
            osquery.TableColumn(name="cluster-ip", type=osquery.STRING),
            osquery.TableColumn(name="external-ip", type=osquery.STRING),
            osquery.TableColumn(name="port", type=osquery.STRING),
            osquery.TableColumn(name="age", type=osquery.STRING),
        ]

    def generate(self, context):
        query_data = []
        config.load_kube_config()
        v1 = client.CoreV1Api()
        ret = v1.list_service_for_all_namespaces(watch=False)

        for i in ret.items:
            row = {}
            row["name"] = i.metadata.name
            row["type"] = i.spec.type
            row["cluster-ip"] = i.spec.cluster_ip
            row["external-ip"] = i.spec.external_i_ps
            row["port"] =  str(i.spec.ports[0].port) + ":" + str(i.spec.ports[0].node_port) + "/" + i.spec.ports[0].protocol
            row["age"] = i.metadata.creation_timestamp

            query_data.append(row)

        return query_data

@osquery.register_plugin
class K8Pods(osquery.TablePlugin):
    def name(self):
        return "k8s_pods"

    def columns(self):
        return [
            osquery.TableColumn(name="name", type=osquery.STRING),
            osquery.TableColumn(name="ready", type=osquery.STRING),
            osquery.TableColumn(name="pod-ip", type=osquery.STRING),
            osquery.TableColumn(name="num_images", type=osquery.STRING),
            osquery.TableColumn(name="status", type=osquery.STRING),
            osquery.TableColumn(name="restarts", type=osquery.STRING),
            osquery.TableColumn(name="age", type=osquery.STRING),
        ]

    def generate(self, context):
        query_data = []
        config.load_kube_config()
        v1 = client.CoreV1Api()
        ret = v1.list_pod_for_all_namespaces(watch=False)

        for i in ret.items:
            #if(i.metadata.namespace!="kube-system"):
            row = {}
            row["name"] = i.metadata.name
            row["ready"] = i.status.container_statuses[0].ready
            row["pod-ip"] = i.status.host_ip

            if(i.status.container_statuses[0].state.running != "None"):
                row["status"] = "Running"
            elif(i.status.container_statuses[0].state.terminated != "None"):
                row["status"] = "Terminated"
            else:
                row["status"] = "Waiting"

            row["restarts"] = i.status.container_statuses[0].restart_count
            
            created = i.metadata.creation_timestamp
            now = datetime.now(timezone.utc)
            diff = now - created
            row["age"] = str(diff.days) + "d"

            images=0
            for c in i.status.container_statuses:
                 images += 1

            row["num_images"] = images

            query_data.append(row)

        return query_data


if __name__ == "__main__":
    osquery.start_extension(name="k8s", version="1.0.0")


    