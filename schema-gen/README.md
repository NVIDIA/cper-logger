# Schema-gen

## Usage

### Step 1

Clone libcper to your local system: `https://github.com/openbmc/libcper.git`

### Step 2

Run the cmdline tool to convert JSON refs to XML schema suitable for redfish:
`python3 schemagen.py convert -s cper-json.json -d ../libcper/specification/json/ -a sections`

## NvidiaCPER v0.9 projection

The libcper JSON representation keeps record metadata in `header`, section
metadata in `sectionDescriptors[]`, and section bodies in `sections[]`.
Redfish exposes selected header and descriptor fields alongside each section in
the flattened `NvidiaCPER` OEM object.

`NvidiaCPER_v0_9_0_projection.json` declares that mapping. It is intentionally
separate from libcper's JSON schemas because it describes the Redfish view, not
libcper's native output shape.

Generate a candidate CSDL from an expanded libcper schema in a temporary
directory so the curated file is not overwritten:

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

The candidate is written to `$SCHEMA_TMP/NvidiaCPER_v1.xml`.

`NvidiaCPER_v1.xml` remains curated to preserve compatibility with the
previously checked-in CSDL. Do not replace the curated file wholesale when
unrelated libcper schema changes appear in generated output.

Each projected property names its libcper `source` and Redfish `target`.
Properties normally inherit their JSON Schema shape from libcper. A
`targetSchema` can instead declare the Redfish shape when it differs, as it
does for the `RecordFlags` and `SectionFlags` enum collections. An optional
`csdlType` selects a more specific CSDL primitive such as `Edm.Guid` or
`Edm.Decimal`.

Generation fails when:

- A configured libcper source path does not exist.
- A target is duplicated or is not a valid CSDL identifier.
- A generated enum is invalid.

The projection describes only the Redfish schema. Cper-logger performs the
matching runtime value transformations in `src/cper.cpp`.

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
