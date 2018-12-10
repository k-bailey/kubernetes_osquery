#!/usr/bin/env python

import osquery
import os

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
        data = os.popen('kubectl get service').read()
        datasplit=data.split()

        i = 6
        while i < len(datasplit):
            row = {}
            row["name"] = datasplit[i]
            row["type"] = datasplit[i+1]
            row["cluster-ip"] = datasplit[i+2]
            row["external-ip"] = datasplit[i+3]
            row["port"] = datasplit[i+4]
            row["age"] = datasplit[i+5]

            query_data.append(row)
            i = i+6

        return query_data

@osquery.register_plugin
class K8Pods(osquery.TablePlugin):
    def name(self):
        return "k8s_pods"

    def columns(self):
        return [
            osquery.TableColumn(name="name", type=osquery.STRING),
            osquery.TableColumn(name="ready", type=osquery.STRING),
            osquery.TableColumn(name="status", type=osquery.STRING),
            osquery.TableColumn(name="restarts", type=osquery.STRING),
            osquery.TableColumn(name="age", type=osquery.STRING),
        ]

    def generate(self, context):
        query_data = []
        data = os.popen('kubectl get pods').read()
        datasplit=data.split()


        i = 5
        while i < len(datasplit):
            row = {}
            row["name"] = datasplit[i]
            row["ready"] = datasplit[i+1]
            row["status"] = datasplit[i+2]
            row["restarts"] = datasplit[i+3]
            row["age"] = datasplit[i+4]

            query_data.append(row)
            i = i+5

        return query_data


if __name__ == "__main__":
    osquery.start_extension(name="k8s", version="1.0.0")