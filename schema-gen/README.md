# Schema-gen

## Usage

### Step 1

Clone libcper to your local system: `https://github.com/openbmc/libcper.git`

### Step 2

Run the cmdline tool to convert JSON refs to XML schema suitable for redfish:
`python3 schemagen.py convert -s cper-json.json -d ../libcper/specification/json/ -a sections`

### Optional

#### Creating a master json schema from all $refs and converting the master json to XML

#### can be done in separate steps

Generate master-schema.json, which consolidates all .json files in the libcper
repo
`python3 schemagen.py json_master -s cper-json.json -d ../libcper/specification/json/`

Convert the master json schema to an XML schema compatible with redfish
`python3 schemagen.py json_to_xml -s master-schema.json -a sections`

### Help

`python3 schemagen.py -h` `python3 schemagen.py json_to_xml -h`
`python3 schemagen.py json_master -h`

## Examples

### Example to aggregate multiple JSON schemas which reference each other with $ref

`python3 schemagen.py json_master -s json_schema.json -d examples`

### Example to convert a clean json schema (with no refs) into XML

1. `python3 schemagen.py json_to_xml -s final_out.json -a sections`
2. `python3 schemagen.py json_to_xml -s final_out.json -x "XML header" \ -f "XML footer" -p "XmlBaseType" -a sections`
