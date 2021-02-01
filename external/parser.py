#!/usr/bin/python
import json
import os
import sys

with open(sys.argv[1]) as file:
    data = json.load(file)

    result = {}

    for d in data:
        d = d.replace('[', '\[').replace(']', '\]')
        cmd = 'grep -rwn -e "{}" {}'.format(d, sys.argv[2])
        stream = os.popen(cmd)
        output = stream.read()
        output = list(filter(None, output.split("\n")))
        output_filtered = []
        for o in output:
            if '$Stub$Proxy.jimple' in o:
                continue
            output_filtered.append(o)

        for o in output_filtered:
            file_name = o.split(":")[0].split("/")[-1]
            if d not in result:
                result[d] = []
            if file_name not in result[d]:
                result[d].append(file_name)

        print("[done] {}".format(d))
        sys.stdout.flush()
        
        out_file = open(sys.argv[2] + "/api_file_mapping.json", "w")
        out_file.write(json.dumps(result, indent=4, sort_keys=True))
        out_file.close()