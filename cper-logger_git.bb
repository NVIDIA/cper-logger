SUMMARY = "Logger for CPERs"
DESCRIPTION = "The CPER logger decodes CPERs received & logs them to the EventLog"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

DEPENDS = " \
  sdbusplus \
  ${@bb.utils.contains('PTEST_ENABLED', '1', 'gtest', '', d)} \
  ${@bb.utils.contains('PTEST_ENABLED', '1', 'gmock', '', d)} \
"

SRC_URI = "file:///home/krajagopalan/cper_logger;branch=main"
SRCREV = "efe9f17637ed27457f2effa52ec215aa093267d9"

PV = "1.0+git${SRCPV}"

SYSTEMD_SERVICE:${PN}:append = "xyz.openbmc_project.cperlogger.service"

S = "${WORKDIR}/git"

inherit meson systemd pkgconfig

PACKAGECONFIG ??= ""

EXTRA_OEMESON = " \
    -Dtests=${@bb.utils.contains('PTEST_ENABLED', '1', 'enabled', 'disabled', d)} \
"

do_install_ptest() {
    install -d ${D}${PTEST_PATH}/test
    cp -rf ${B}/*_test ${D}${PTEST_PATH}/test/
}
