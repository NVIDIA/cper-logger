#!/usr/bin/env python3
# coding: utf-8
"""
Allows conversion of multiple json schemas into a single
master schema by replacing $ref(s) with the expanded file contents

Modify certain keys of a schema by applying a transformation

Generate an XML schema from a json schema defined for CPERs

@author: Aushim Nagarkatti
"""

import argparse

# imports
import json
import os
import re
import sys

version = "v0_9_0"

HEADER = f"""<?xml version="1.0" encoding="UTF-8"?>
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:Reference Uri="http://docs.oasis-open.org/odata/odata/v4.0/errata03/csd01/complete/vocabularies/Org.OData.Core.V1.xml">
    <edmx:Include Namespace="Org.OData.Core.V1" Alias="OData"/>
  </edmx:Reference>
  <edmx:Reference Uri="http://redfish.dmtf.org/schemas/v1/RedfishExtensions_v1.xml">
    <edmx:Include Namespace="Validation.v1_0_0" Alias="Validation"/>
    <edmx:Include Namespace="RedfishExtensions.v1_0_0" Alias="Redfish"/>
  </edmx:Reference>
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="NvidiaCPER"> </Schema>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="NvidiaCPER.{version}">"""

FOOTER = """
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"""

CSDL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ProjectionError(ValueError):
    """A CPER-to-CSDL projection is malformed or does not match its source."""


def schema_has_type(schema, expected):
    """Return whether a JSON Schema type includes the expected type."""
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return expected in schema_type
    return schema_type == expected


class SchemaGenerator:
    """
    Class for creating a single json schema by combining refs
    and allowing modification of property keys.
    """

    def __init__(self, rootpath, base_schema):
        """
        Args:
            rootpath (string): Path to directory containing all json schema files
            base_schema (string): Path to root json schema file
        """
        self.ref_paths = {}
        self.rootpath = rootpath
        self.base_schema = json.load(open(os.path.join(rootpath, base_schema)))
        self.map_schemas(rootpath)

    def map_schemas(self, schema_dir):
        """
        Create a map of all the json files in the directories below root dir
        Args:
            schema_dir (string): Path to root directory containing all json schema files
        """
        for root, _, files in os.walk(schema_dir):
            for filename in files:
                if filename.endswith(".json"):
                    schema_path = os.path.join(root, filename)
                    self.ref_paths[filename] = schema_path

    def refresolve(self, ref):
        """Load and return a referenced JSON Schema."""
        if ref not in self.ref_paths:
            print("Error no ref path named: ", ref)
            return
        with open(self.ref_paths[ref], "r") as schema_file:
            return json.load(schema_file)

    def replace_refs(self, schema):
        """
        Replace all references of $ref with actual json file contents
        Args:
            schema (string): Original json schema file as a string
        Returns:
            result (string): transformed json schema file
        """
        if isinstance(schema, dict):
            if "$ref" in schema:
                ref = os.path.basename(schema["$ref"])
                resolved_schema = self.refresolve(ref)
                replaced_ref = self.replace_refs(resolved_schema)
                replaced_ref.pop("$schema", None)
                return replaced_ref
            else:
                for key, value in schema.items():
                    schema[key] = self.replace_refs(value)
        elif isinstance(schema, list):
            schema = [self.replace_refs(item) for item in schema]

        return schema

    # Modify named properties in a json schema
    def modify_schema(self, schema, keytomod):
        """
        Replace all references of $ref with actual json file contents
        Args:
            schema (string): Original json schema file as a string
            keytomod (string): A particular json property that needs modification
        Returns:
            result (string): json schema file with modified property
        """
        if isinstance(schema, dict):
            for key, value in schema.items():
                if key == keytomod:
                    propname = schema[key]
                    # Define your own transform in place of capitalize()
                    schema[key] = self.capitalize(propname)
                else:
                    schema[key] = self.modify_schema(value)

            return schema

        elif isinstance(schema, list):
            schema = [self.modify_schema(item) for item in schema]

        return schema

    def capitalize(self, propname):
        """Uppercase the first character of a property name."""
        return propname[0].upper() + propname[1:]


class CperProjection:
    """Map properties from an expanded libcper schema into CSDL."""

    def __init__(self, definition, source_name="<projection>"):
        """Validate and store CPER-to-CSDL property mappings."""
        if not isinstance(definition, dict):
            raise ProjectionError(f"{source_name}: root must be an object")
        self.source_name = source_name
        properties = definition.get("properties")
        if not isinstance(properties, list) or not properties:
            raise ProjectionError(
                f"{source_name}: properties must be a non-empty array"
            )

        self.properties = []
        targets = set()
        for index, mapping in enumerate(properties):
            context = f"{source_name}: properties[{index}]"
            if not isinstance(mapping, dict):
                raise ProjectionError(f"{context}: must be an object")
            source = mapping.get("source")
            target = mapping.get("target")
            if not isinstance(source, str) or not source:
                raise ProjectionError(
                    f"{context}: source must be a non-empty string"
                )
            if (
                not isinstance(target, str)
                or CSDL_IDENTIFIER.fullmatch(target) is None
            ):
                raise ProjectionError(
                    f"{context}: target must be a CSDL identifier"
                )
            target = target[0].upper() + target[1:]
            if target in targets:
                raise ProjectionError(
                    f'{context}: duplicate target property "{target}"'
                )
            target_schema = mapping.get("targetSchema")
            if target_schema is not None and not isinstance(
                target_schema, dict
            ):
                raise ProjectionError(
                    f"{context}: targetSchema must be an object"
                )
            csdl_type = mapping.get("csdlType")
            if csdl_type is not None and not isinstance(csdl_type, str):
                raise ProjectionError(
                    f"{context}: csdlType must be a string"
                )
            targets.add(target)
            self.properties.append(
                {
                    "source": source,
                    "target": target,
                    "targetSchema": target_schema,
                    "csdlType": csdl_type,
                }
            )

    @classmethod
    def from_file(cls, filename):
        """Load a CPER projection definition from a JSON file."""
        try:
            with open(filename, "r", encoding="utf-8") as projection_file:
                definition = json.load(projection_file)
        except (OSError, json.JSONDecodeError) as error:
            raise ProjectionError(
                f"Unable to load projection {filename}: {error}"
            ) from error
        return cls(definition, filename)

    def _find_source_document(self, schema):
        """Find the schema document containing all projected sources."""
        source_roots = {
            mapping["source"].split(".", 1)[0].removesuffix("[]")
            for mapping in self.properties
        }
        candidates = [schema]
        if isinstance(schema.get("oneOf"), list):
            candidates.extend(schema["oneOf"])
        matches = [
            candidate
            for candidate in candidates
            if isinstance(candidate, dict)
            and source_roots
            <= set(candidate.get("properties", {}))
        ]
        if len(matches) != 1:
            raise ProjectionError(
                f"{self.source_name}: expected one schema containing "
                f"projection sources, found {len(matches)}"
            )
        return matches[0]

    def _resolve_source(self, document, path):
        """Resolve a dotted projection path to its JSON Schema node."""
        current = document
        for segment in path.split("."):
            is_array = segment.endswith("[]")
            name = segment[:-2] if is_array else segment
            properties = current.get("properties")
            if not isinstance(properties, dict) or name not in properties:
                raise ProjectionError(
                    f'{self.source_name}: source path "{path}" does not '
                    f'exist at "{name}"'
                )
            current = properties[name]
            if is_array:
                if not schema_has_type(current, "array"):
                    raise ProjectionError(
                        f'{self.source_name}: "{name}" in source path '
                        f'"{path}" is not an array'
                    )
                current = current.get("items")
                if not isinstance(current, dict):
                    raise ProjectionError(
                        f'{self.source_name}: array "{name}" has no object '
                        "items schema"
                    )
        return current

    def _build_target_schema(self, mapping, source_schema):
        """Build the target schema with projection-specific overrides."""
        target_schema = mapping.get("targetSchema")
        if target_schema is None:
            target_schema = source_schema
        if not isinstance(target_schema, dict):
            raise ProjectionError(
                f'{self.source_name}: schema for target '
                f'"{mapping["target"]}" must be an object'
            )
        target_schema = target_schema.copy()
        target_schema.pop("$id", None)
        target_schema.pop("$schema", None)
        if mapping.get("csdlType") is not None:
            target_schema["x-csdl-type"] = mapping["csdlType"]
        return target_schema

    def resolve(self, schema):
        """Resolve mappings against an expanded libcper root schema."""
        document = self._find_source_document(schema)
        resolved = {}
        for mapping in self.properties:
            source_schema = self._resolve_source(
                document, mapping["source"]
            )
            resolved[mapping["target"]] = self._build_target_schema(
                mapping, source_schema
            )
        return resolved


class JsontoXml:
    """
    Class for creating an XML version of a JSON schema.
    Created specifically to transform CPER json schemas into xml.
    Note: Refer to examples/json_schema.json for details
    on json schema fields expected by this script.
    """

    def __init__(
        self,
        debug=False,
        parent_basetype=None,
        required=False,
        start_property="sections",
        projection=None,
    ):
        """
        Args:
            debug (bool): Enables verbose printing of schema and properties in each iteration. Default is False.
            parent_basetype (string): Base type of XML schema, which is referred to by all child properties
            required (bool): Populate only "required" properties of the json schema in the XML. Default is False.
            start_property (string): Change root element of the json schema, so XML will only be a subset. This should
                                    be defined in the "properties" field
            projection (CperProjection): Optional mapping of properties from
                                        outside start_property into the CSDL
                                        root type.
        """
        self.typemap = {
            "integer": "Edm.Int64",
            "uint64": "Edm.Int64",
            "string": "Edm.String",
            "boolean": "Edm.Boolean",
        }
        self.debug = debug
        # add a parent_basetype to instruct code to always
        # use this as the inferred base data type. Else,
        # the base data type for each property will be its immediate parent
        self.parent_basetype = parent_basetype
        self.required = required
        self.start_property = start_property
        self.projection = projection
        self.error_status_present = False
        self.enum_types = {}

        # Resolves $id and property duplications
        # These properties are also cast into baseid to prevent duplications
        self.skip_idprop = [
            "GenericProcessor",
            "Ia32X64Processor",
            "ArmProcessor",
            "Memory",
            "Memory2",
            "Pcie",
            "PciBus",
            "PciComponent",
            "Firmware",
            "GenericDmar",
            "VtdDmar",
            "IommuDmar",
            "CcixPer",
            "CxlProtocol",
            "CxlComponent",
            "Nvidia",
            "Ampere",
            "Unknown",
            "cacheError",
            "tlbError",
            "busError",
        ]
        # Properties that are repeatable in the XML schema
        # But have unique parents, like TransactionType and Operation
        # The baseid
        self.repeatable_props = [
            "TransactionType",
            "Operation",
        ]
        # Skips properties from being added to XML
        self.skip_props = []

    def register_enum(self, owner_type, property_name, schema):
        """Register a scalar or collection string enum."""
        if not isinstance(schema, dict):
            raise ProjectionError(
                f"Enum property {owner_type}.{property_name} "
                "schema must be an object"
            )

        enum_schema = schema
        if schema_has_type(schema, "array"):
            enum_schema = schema.get("items", {})
            if not isinstance(enum_schema, dict):
                raise ProjectionError(
                    f"Enum property {owner_type}.{property_name} "
                    "array items must be an object"
                )

        members = enum_schema.get("enum")
        if members is None:
            return None

        if not isinstance(members, list) or not members:
            raise ProjectionError(
                f"Enum property {owner_type}.{property_name} "
                "must declare a non-empty enum array"
            )

        if not schema_has_type(enum_schema, "string"):
            raise ProjectionError(
                f"Enum property {owner_type}.{property_name} "
                "must be a string enum"
            )

        enum_name = schema.get("x-csdl-enum-type")
        if enum_name is None:
            enum_name = property_name[:1].upper() + property_name[1:]
        identifiers = (enum_name, *members)
        if any(
            not isinstance(identifier, str)
            or CSDL_IDENTIFIER.fullmatch(identifier) is None
            for identifier in identifiers
        ):
            raise ProjectionError(
                f"Enum property {owner_type}.{property_name} "
                "contains an invalid CSDL identifier"
            )

        if len(set(members)) != len(members):
            raise ProjectionError(
                f"Enum property {owner_type}.{property_name} "
                "contains duplicate members"
            )

        enum_definition = (tuple(members), owner_type)
        existing_definition = self.enum_types.get(enum_name)
        if (
            existing_definition is not None
            and existing_definition[0] != enum_definition[0]
        ):
            raise ProjectionError(
                f"Enum {enum_name} is defined with conflicting members"
            )

        if existing_definition is None:
            self.enum_types[enum_name] = enum_definition
        return enum_name

    def add_projection(self, xml, target_type, target_schemas):
        """Add resolved projection declarations to a generated CSDL type."""
        root_marker = f'      <ComplexType Name="{target_type}">\n'
        if xml.count(root_marker) != 1:
            raise ProjectionError(
                f"Expected exactly one {target_type} CSDL root type"
            )

        root_start = xml.index(root_marker)
        root_end = xml.index("      </ComplexType>\n", root_start)
        root_xml = xml[root_start:root_end]
        projected_types = ""
        projected_properties = ""

        for property_name, property_schema in target_schemas.items():
            property_marker = f'<Property Name="{property_name}" '
            if property_marker in root_xml:
                raise ProjectionError(
                    f"Projection target {target_type}.{property_name} "
                    "already exists"
                )

            enum_type = self.register_enum(
                target_type, property_name, property_schema
            )
            projected_properties += self.encode_xml(
                "",
                property_name,
                "property",
                type=property_schema.get("type"),
                basetype=target_type,
                enum_type=enum_type,
                csdl_type=property_schema.get("x-csdl-type"),
            )

            if schema_has_type(property_schema, "object") or schema_has_type(
                property_schema, "array"
            ):
                type_xml = self.jsonschema_to_xml(
                    property_schema,
                    property_name,
                    "",
                    prevproperty=target_type,
                )[0]
                if type_xml:
                    projected_types += type_xml

        return xml.replace(
            root_marker,
            projected_types + root_marker + projected_properties,
            1,
        )

    def add_registered_enums(self, xml):
        """Insert discovered enum declarations before their owning types."""
        for enum_name, (members, owner_type) in self.enum_types.items():
            type_marker = f'      <ComplexType Name="{owner_type}">\n'
            if xml.count(type_marker) != 1:
                raise ValueError(
                    f"Expected exactly one {owner_type} complex type"
                )
            member_xml = "".join(
                f'          <Member Name="{member}"/>\n'
                for member in members
            )
            enum_xml = (
                f'      <EnumType Name="{enum_name}">\n'
                + member_xml
                + "      </EnumType>\n\n"
            )
            xml = xml.replace(type_marker, enum_xml + type_marker, 1)

        return xml

    def jsonschema_to_xml(self, schema, basetype, baseid, prevproperty=""):
        """
        Replace all references of $ref with actual json file contents
        Args:
            schema (string): Original json schema file as a string
            basetype (string): Parent data type of property. Use same as parent_basetype if the entire json schema is being used.
            baseid (string): Reference to closest ancestor $id property. This is used to provide unique namespaces to repeatable properties.
            baseid is also concatenated with self.skip_idprop. This will recursively extend as we go deeper into the schema.
        Returns:
            result (string): XML schema for CPER output
        """
        if self.debug:
            print("\n\n\n\n")
            print(json.dumps(schema, indent=1))
        if isinstance(schema, dict):
            req = schema.get("required")
            if req is not None:
                assert isinstance(req, list), "request field is not a list"
                if (baseid + basetype).lower() == "errorstatuserrortype":
                    if not self.error_status_present:
                        self.error_status_present = True
                    else:
                        return ("", "")

                props = schema.get("properties")

                if not props:
                    print(
                        "'Required' field was found. 'Properties' field not found for: \n",
                        schema,
                    )
                    return 1

                id = schema.get("$id")
                if id and ("namevaluepair" not in id):
                    basetype = self.format_propname(id)
                    if basetype in self.skip_idprop:
                        k = list(schema["properties"].keys())[0]
                        return (
                            self.jsonschema_to_xml(
                                schema["properties"][k],
                                basetype,
                                baseid,
                                prevproperty,
                            )[0],
                            basetype,
                        )

                start, end = self.encode_xml(baseid, basetype, "base")
                property_xml = start
                entity_name = baseid + basetype[0].upper() + basetype[1:]

                # We need a way to return baseid to the parent property when the baseids
                # are encapsulated in a list, like in oneOf[]
                ret_id = None
                if id:
                    baseid = self.format_propname(id)
                    ret_id = baseid
                    self.id = id

                if "validationbits" in basetype.lower():
                    baseid += prevproperty

                xml_ret = ""
                # Even without $id, this can populate baseid
                if basetype in self.skip_idprop:
                    baseid += basetype[0].upper() + basetype[1:]
                for prop, propval in props.items():
                    if self.required and (prop not in req):
                        continue
                    if self.debug:
                        print(prop)
                    # Get each property
                    if prop.lower() == "validationbits":
                        baseid += basetype
                    subschema = propval
                    if (baseid + prop).lower() in self.skip_props:
                        property_xml += self.handle_errorinfo(baseid, basetype)
                    else:
                        enum_type = self.register_enum(
                            entity_name, prop, subschema
                        )
                        property_xml += self.encode_xml(
                            baseid,
                            prop,
                            "property",
                            type=subschema["type"],
                            basetype=basetype,
                            enum_type=enum_type,
                            csdl_type=subschema.get("x-csdl-type"),
                        )
                    xml_ret += self.jsonschema_to_xml(
                        propval, prop, baseid, prevproperty=basetype
                    )[0]

                property_xml += end
                xml_ret += property_xml
                if self.debug:
                    print(xml_ret)

                return (xml_ret, ret_id)

            else:
                if schema.get("oneOf"):
                    return self.jsonschema_to_xml(
                        schema["oneOf"], basetype, baseid, prevproperty
                    )
                elif schema.get("items"):
                    return self.jsonschema_to_xml(
                        schema["items"], basetype, baseid, prevproperty
                    )
                else:
                    return ("", None)

        elif isinstance(schema, list):
            property_xml = ""
            properties_oneof = []
            for i, item in enumerate(schema):
                xml, ret_id = self.jsonschema_to_xml(
                    item, basetype, baseid, ""
                )
                property_xml += xml
                if ret_id:
                    properties_oneof.append(ret_id)
                else:
                    idstr = (
                        "cper-json-"
                        + baseid.lower()
                        + "-"
                        + basetype.lower()
                        + str(i)
                    )
                    print('"$id": "' + idstr + '",')

            # This works only if $id is defined for every oneof[]
            if len(properties_oneof):
                xml, end = self.encode_xml(baseid, basetype, "base")
                for prop in properties_oneof:
                    xml += self.encode_xml(
                        baseid,
                        prop,
                        "property",
                        "object",
                        basetype=basetype,
                    )

                xml += end
            return (property_xml + xml, None)

    def schema_parser(self, schema, basetype="NvidiaCPER", baseid=""):
        """
        Wrapper around jsonschema_to_xml
        Args:
            header (string): XML header to be appended to output
            footer (string): XML footer to be appended to output
            schema (string): Original json schema file as a string
            basetype (string): Parent data type of property. Use same as parent_basetype if the entire json schema is being used.
            baseid (string): Reference to closest ancestor $id property. This is used to provide unique namespaces to repeatable properties.
                             User should leave this empty.
        Returns:
            result (string): XML schema for CPER output
        """
        xml_out = HEADER
        self.enum_types.clear()
        self.error_status_present = False
        projected_schemas = {}
        start_property = self.start_property
        if self.projection is not None:
            projected_schemas = self.projection.resolve(schema)
        while not schema.get(start_property):
            if schema.get("oneOf"):
                schema = schema["oneOf"][0]
                continue
            elif schema.get("required"):
                if start_property in schema["required"]:
                    schema = schema["properties"]
                    continue
            else:
                print("ERROR could not find ", start_property)
                return
        schema = schema[start_property]
        base_schema = schema
        generated_xml = self.jsonschema_to_xml(
            base_schema, basetype=basetype, baseid=baseid
        )[0]
        if projected_schemas:
            generated_xml = self.add_projection(
                generated_xml, basetype, projected_schemas
            )
        generated_xml = self.add_registered_enums(generated_xml)
        xml_out += generated_xml
        xml_out += FOOTER

        return xml_out

    def get_schema_file(self, filename):
        """Load and return a JSON Schema file."""
        with open(filename, "r") as schema_file:
            schema = json.load(schema_file)
        return schema

    def format_propname(self, name):
        """
        Change how property names are displayed
        Args:
            name (string): Property name
        Returns:
            result (string): Formatted name
        """
        names_l = name.split("-")
        # For CPER schemas, name is of the format
        # cper-json-error-status or cper-json-firmware-section
        ret = ""
        for n in names_l[2:]:
            if n == "section":
                continue
            ret += n.title()

        # These need to be handled differently
        # to match output spec
        if ret == "Cacheerror":
            return "CacheError"
        if ret == "Tlberror":
            return "TlbError"
        if ret == "Buserror":
            return "BusError"
        return ret

    def handle_errorinfo(self, baseid, basetype):
        """Generate the standard cache and TLB error properties."""
        xml = ""
        xml += self.encode_xml(
            baseid,
            "CacheError",
            "property",
            "object",
            basetype=basetype,
        )
        xml += self.encode_xml(
            baseid, "TlbError", "property", "object", basetype=basetype
        )
        return xml

    def encode_xml(
        self,
        baseid,
        val,
        ele,
        type=None,
        basetype=None,
        enum_type=None,
        csdl_type=None,
    ):
        """
        Format XML output
        Args:
            baseid (string): Reference to closest ancestor $id property. This is used to provide unique namespaces to repeatable properties.
                            User should leave this empty.
            val (string): Property or Entity name
            ele (string): 'base' for Entity, 'property' for Property
            type (string): Used for converting json type to XML type
            basetype (string): Parent data type of property.
            enum_type (string): CSDL enum type registered for the property.
            csdl_type (string): Explicit CSDL primitive type override.

        Returns:
            result (string): XML schema for CPER output
        """
        # val = self.format_propname(val)
        entity_name = baseid + val[0].upper() + val[1:]
        prop_name = val[0].upper() + val[1:]
        prop_type = baseid + val[0].upper() + val[1:]
        if ele == "base":
            return (
                '\n      <ComplexType Name="' + entity_name + '">\n',
                "      </ComplexType>\n",
            )
        elif ele == "property":
            if self.parent_basetype:
                basetype = self.parent_basetype
            else:
                basetype = basetype[0].upper() + basetype[1:]
            if enum_type:
                enum_namespace = (
                    self.parent_basetype or f"NvidiaCPER.{version}"
                )
                property_type = enum_namespace + "." + enum_type
                if type == "array":
                    property_type = "Collection(" + property_type + ")"
                return (
                    '          <Property Name="'
                    + prop_name
                    + '" Type="'
                    + property_type
                    + '"></Property>\n'
                )
            if csdl_type:
                return (
                    '          <Property Name="'
                    + prop_name
                    + '" Type="'
                    + csdl_type
                    + '"></Property>\n'
                )
            if type == "object" or type == "array":
                if type == "array":
                    return (
                        '          <Property Name="'
                        + prop_name
                        + '" Type="Collection('
                        + basetype
                        + "."
                        + prop_type
                        + ')"></Property>\n'
                    )
                return (
                    '          <Property Name="'
                    + prop_name
                    + '" Type="'
                    + basetype
                    + "."
                    + prop_type
                    + '"></Property>\n'
                )
            else:
                return (
                    '          <Property Name="'
                    + prop_name
                    + '" Type="'
                    + self.typemap[type]
                    + '"></Property>\n'
                )
        else:
            print("wrong value for XML element: ", ele)

    def append_to_xml(self, xml, arg):
        """Append an XML fragment to generated XML text."""
        return xml + arg

    def validate_xml(self, xmlf):
        """Report duplicate complex type names in an XML file."""
        print("Validating XML")
        entity_names = []
        with open(xmlf, "r") as f:
            for line in f:
                if "ComplexType Name" in line:
                    name = line.strip().split("=")[1]
                    if name in entity_names:
                        print("Duplicate: ", name)
                    else:
                        entity_names.append(name)


def main():
    """Run the requested JSON Schema or CSDL generation command."""
    parser = argparse.ArgumentParser(
        prog="JsonSchemaToXML",
        description="Create a master json schema by replacing refs, modify json properties, and convert it to XML.",
        epilog="Refer to examples/json_schema.json for json schema parameters expected by this program.",
    )

    subparsers = parser.add_subparsers(dest="subparser_name", required=True)

    parser_a = subparsers.add_parser(
        "json_master",
        help="Select this option to convert an assortment of json schemas into a single schema by using the $ref variable.",
    )
    parser_b = subparsers.add_parser(
        "json_to_xml",
        help="Create an XML schema out of a json schema (containing no $ref)",
    )

    parser_c = subparsers.add_parser(
        "convert",
        help="Create an XML schema out of a json schema (might contain $ref)",
    )

    parser_a.add_argument("-v", "--verbose", action="store_true")
    parser_a.add_argument(
        "-s",
        "--schema",
        nargs=1,
        help="Input json schema",
        required=True,
    )

    parser_c.add_argument("-v", "--verbose", action="store_true")
    parser_c.add_argument(
        "-s",
        "--schema",
        nargs=1,
        help="Input json schema",
        required=True,
    )

    parser_a.add_argument(
        "-d",
        "--schemadir",
        nargs=1,
        help="Root location of json schema directory",
        required=True,
    )

    parser_c.add_argument(
        "-d",
        "--schemadir",
        nargs=1,
        help="Root location of json schema directory",
        required=True,
    )

    parser_b.add_argument("-v", "--verbose", action="store_true")
    parser_b.add_argument(
        "-s",
        "--schema",
        nargs=1,
        help="Input json schema",
        required=True,
    )
    parser_b.add_argument(
        "-p",
        "--parent-basetype",
        nargs=1,
        help="Basetype for all elements to inherit",
    )

    parser_b.add_argument(
        "-a",
        "--argstart",
        nargs=1,
        help="Property of json schema to start parsing from",
    )

    parser_c.add_argument(
        "-a",
        "--argstart",
        nargs=1,
        help="Property of json schema to start parsing from",
    )

    parser_c.add_argument(
        "-p",
        "--parent-basetype",
        nargs=1,
        help="Basetype for all elements to inherit",
    )

    for xml_parser in (parser_b, parser_c):
        xml_parser.add_argument(
            "-j",
            "--projection",
            help=(
                "JSON projection that maps properties outside --argstart "
                "into the generated CSDL root"
            ),
        )

    parser_b.add_argument("-x", "--header", nargs=1, help="XML header")
    parser_b.add_argument("-f", "--footer", nargs=1, help="XML footer")
    parser_b.add_argument(
        "-r",
        "--required",
        help="Only consider required fields",
        action="store_true",
    )
    parser_b.add_argument(
        "-z", "--validate", help="Validate XML", action="store_true"
    )
    parser_c.add_argument(
        "-z", "--validate", help="Validate XML", action="store_true"
    )
    parser_c.add_argument(
        "-r",
        "--required",
        help="Only consider required fields",
        action="store_true",
    )

    args = parser.parse_args()

    projection = None
    projection_file = getattr(args, "projection", None)
    if projection_file:
        projection = CperProjection.from_file(projection_file)

    if args.subparser_name == "json_master":
        print("Creating master json")
        # Master JSON Schema creation
        schema_directory = args.schemadir[0]

        schema = SchemaGenerator(schema_directory, args.schema[0])

        base = schema.base_schema
        master_schema = schema.replace_refs(base)

        output = "master-schema.json"
        print("Output filename: ", output)
        with open(output, "w") as f:
            print(json.dumps(master_schema, indent=1), file=f)
            # json.dump(master_schema, f)

    elif args.subparser_name == "json_to_xml":
        print("Creating json-schema -> xml")

        if args.header:
            header = args.header[0]
        else:
            header = ""

        if args.footer:
            footer = args.footer[0]
        else:
            footer = ""

        if args.parent_basetype:
            parent_basetype = args.parent_basetype[0]
        else:
            parent_basetype = "NvidiaCPER." + version

        if args.argstart:
            argstart = args.argstart[0]
        else:
            argstart = "sections"

        print("header is: ", header)
        print("footer is: ", footer)
        print("parent_basetype is: ", parent_basetype)
        print("required is: ", args.required)

        # #JSON to XML conversion
        xml_obj = JsontoXml(
            debug=args.verbose,
            parent_basetype=parent_basetype,
            required=args.required,
            start_property=argstart,
            projection=projection,
        )

        # logfile='cper-json-full-log.json'
        # masterfile = 'master-schema.json'
        if args.validate:
            xml_obj.validate_xml(args.schema[0])
            exit(0)

        schema = xml_obj.get_schema_file(args.schema[0])
        output = xml_obj.schema_parser(schema)

        out_file = "master-schema.xml"
        print("Output filename: ", out_file)
        with open(out_file, "w") as f:
            print(output, file=f)

    elif args.subparser_name == "convert":
        print("Creating master json")
        # Master JSON Schema creation
        json_schema_directory = args.schemadir[0]

        schema = SchemaGenerator(json_schema_directory, args.schema[0])

        base = schema.base_schema
        master_schema = schema.replace_refs(base)

        print("Creating json-schema -> xml")

        if args.parent_basetype:
            parent_basetype = args.parent_basetype[0]
        else:
            parent_basetype = "NvidiaCPER." + version

        if args.argstart:
            argstart = args.argstart[0]
        else:
            argstart = "sections"

        print("parent_basetype is: ", parent_basetype)
        print("required is: ", args.required)

        # #JSON to XML conversion
        xml_obj = JsontoXml(
            debug=args.verbose,
            parent_basetype=parent_basetype,
            required=args.required,
            start_property=argstart,
            projection=projection,
        )

        output = xml_obj.schema_parser(master_schema)

        out_file = "NvidiaCPER_v1.xml"
        print("Saving output to: ", out_file)
        with open(out_file, "w") as f:
            print(output, file=f)

        if args.validate:
            xml_obj.validate_xml(out_file)
            exit(0)

    else:
        exit(1)


if __name__ == "__main__":
    try:
        main()
    except ProjectionError as error:
        print(f"Projection error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
