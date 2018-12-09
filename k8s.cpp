/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <regex>
#include <string>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

#include "osquery/remote/http_client.h"

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief local port where the kubernetes API is listening
 
 * By default this is targeted at the unauthenticated API @ localhost:8080
 * Adjust according to your environments configuration
 */
FLAG(string,
     kubernetes_api,
     "http://localhost:8080",
     "Kubernetes API location");

namespace tables {

/**
 * @brief Makes Kubernetes API calls.
 *
 * @param uri Relative URI.
 * @param tree Property tree where JSON result is stored.
 * @return Status with 0 code on success. Non-negative status with error
 *         message.
 */
Status k8s_Api(const std::string& uri, pt::ptree& tree) {

  http::Request req(uri);
  http::Client::Options options;
  options.timeout(3);
  http::Client client(options);

  try {
    http::Response res = client.get(req);
    boost::uint16_t http_status_code = res.status();

    if (http_status_code != 200) {
      VLOG(1) << "Unexpected HTTP response for: " << uri
              << " Status: " << http_status_code;
      return Status(1, "Error connecting to kubernetes API");
    }
    
    try {
      std::stringstream json_stream;
      json_stream << res.body();
      pt::read_json(json_stream, tree);
      return Status(0, "ok");

    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Error reading the json: " << e.what();
      return Status(1, "Error reading kubernetes API response for " + uri + ": " + e.what());
    }

  } catch (std::system_error& e) {
    VLOG(1) << "Request for " << uri << " failed: " << e.what();
  }

  return Status(1, "Unknown error." );
}


/**
 * @brief Entry point for k8s_services table.
 */
QueryData getServices(QueryContext& context) {
  QueryData results;
  pt::ptree services;
  Status s = k8s_Api(FLAGS_kubernetes_api + "/api/v1/services", services);
  
  if (!s.ok()) {
    VLOG(1) << "Error calling the kubernetes API to get nodes: " << s.what();
    return results;
  }
  
  const pt::ptree& items = services.get_child("items");
  for (const auto& entry : items) {
    const pt::ptree& item = entry.second;
    Row r;
    r["name"] = item.get<std::string>("metadata.name", "");
    r["namespace"] = item.get<std::string>("metadata.namespace", "");
    r["creationTimestamp"] = item.get<std::string>("metadata.creationTimestamp", "");
    r["clusterIP"] = item.get<std::string>("spec.clusterIP", "");
    r["selfLink"] = item.get<std::string>("metadata.selfLink", "");
    r["uid"] = item.get<std::string>("metadata.uid", "");
    r["resourceVersion"] = item.get<std::string>("metadata.resourceVersion", "");

    std::vector<std::string> ports;
    for (const auto& entry2 : item.get_child("spec.ports")) {
      const pt::ptree& port = entry2.second;
      ports.push_back(
        port.get<std::string>("name", "no-name") + " - " + 
        port.get<std::string>("protocol", "") + " - " + 
        port.get<std::string>("port", "") + ":" + 
        port.get<std::string>("targetPort", ""));
    }
    r["ports"] = osquery::join(ports, ", ");

    results.push_back(r);
  }
  return results;
}

QueryData getPods(QueryContext& context) {
  QueryData results;
  pt::ptree pods;
  Status s = k8s_Api(FLAGS_kubernetes_api + "/api/v1/pods", pods);
  
  if (!s.ok()) {
    VLOG(1) << "Error calling the kubernetes API to get nodes: " << s.what();
    return results;
  }

  const pt::ptree& items = pods.get_child("items");
  for (const auto& entry : items) {
    const pt::ptree& item = entry.second;
    Row r;
    r["name"] = item.get<std::string>("metadata.name", "");
    r["namespace"] = item.get<std::string>("metadata.namespace", "");
    r["hostIP"] = item.get<std::string>("status.hostIP", "");
    r["podIP"] = item.get<std::string>("status.podIP", ""); 
    r["startTime"] = item.get<std::string>("status.startTime", "");
    r["phase"] = item.get<std::string>("status.phase", ""); 

    //const pt::ptree& containers = item.get_child("spec.containers");
    //std::vector<std::string> images;
    //for (const auto& entry2 : containers) {
    //  const pt::ptree& container = entry2.second;
    //  images.push_back(container.get<std::string>("image",""));
    //}
    //r["images"] = osquery::join(images, ", ");

    results.push_back(r);
  }

  return results;
}

} //namespace tables
} //namespace osquery