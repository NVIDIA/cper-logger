# Schema-gen

## Usage

### Step 1

Clone libcper to your local system: `https://github.com/openbmc/libcper.git`

### Step 2

Run the cmdline tool to convert JSON refs to XML schema suitable for redfish:
`python3 schemagen.py convert -s cper-json.json -d ../libcper/specification/json/ -a sections`

## NvidiaCPER v0.9 projection

In libcper JSON, record metadata is under `header`, section descriptors are
under `sectionDescriptors[]`, and decoded sections are under `sections[]`. The
Redfish `NvidiaCPER` object combines a decoded section with selected metadata
from the record header and its matching section descriptor.

For example, the seven metadata properties added in v0.9 are mapped as follows:

| libcper source | Redfish property | CSDL type |
| --- | --- | --- |
| `header.revision` | `CPERRevision` | `NvidiaCPER.v0_9_0.CPERRevision` |
| `header.partitionID` | `PartitionID` | `Edm.Guid` |
| `header.creatorID` | `CreatorID` | `Edm.Guid` |
| `header.notificationType.type` | `NotificationTypeName` | `Edm.String` |
| `header.recordID` | `RecordID` | `Edm.Decimal` |
| `header.flags.value` | `RecordFlags` | `Collection(NvidiaCPER.v0_9_0.RecordFlag)` |
| `sectionDescriptors[].flags` | `SectionFlags` | `Collection(NvidiaCPER.v0_9_0.SectionFlag)` |

`NvidiaCPER_v0_9_0_projection.json` tells the schema generator to add these
properties to the generated `NvidiaCPER` type. It is separate from libcper's
JSON schemas because it describes the Redfish layout rather than libcper's JSON
layout.

Run the generator from a temporary directory. It writes
`NvidiaCPER_v1.xml` to the current directory:

```sh
CPER_LOGGER=/path/to/cper-logger
LIBCPER=/path/to/libcper
SCHEMA_TMP="$(mktemp -d)"

cd "$SCHEMA_TMP"
python3 "$CPER_LOGGER/schema-gen/schemagen.py" convert \
    -s cper-json.json \
    -d "$LIBCPER/specification/json/" \
    -a sections \
    -j "$CPER_LOGGER/schema-gen/NvidiaCPER_v0_9_0_projection.json"
```

Each projected property can contain:

- `source`: The path in libcper's JSON Schema. `[]` indicates an array.
- `target`: The property name added to `NvidiaCPER`.
- `targetSchema`: An optional schema used when the Redfish type differs from
  the libcper type.
- `csdlType`: An optional CSDL type such as `Edm.Guid` or `Edm.Decimal`.

`RecordFlags` and `SectionFlags` use `targetSchema` because libcper represents
the source flags as bitmask-related objects, while Redfish represents them as
collections of enum strings.

Generation fails when:

- The projection file is malformed.
- A source path cannot be found.
- A target is duplicated or is not a valid CSDL identifier.
- An enum definition is invalid or conflicts with another enum.

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
