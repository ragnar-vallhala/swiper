# FindPCAP.cmake
find_path(PCAP_INCLUDE_DIR
  NAMES pcap/pcap.h pcap.h
  PATHS /usr/include /usr/local/include
)

find_library(PCAP_LIBRARY
  NAMES pcap wpcap
  PATHS /usr/lib /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
  DEFAULT_MSG
  PCAP_LIBRARY
  PCAP_INCLUDE_DIR
)

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)

if(PCAP_FOUND)
  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif()