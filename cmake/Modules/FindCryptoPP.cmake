SET(CRYPTOPP_SEARCH_PATHS
        ~/Library/Frameworks
        /Library/Frameworks
        /usr/local
        /usr
        /sw # Fink
        /opt/local # DarwinPorts
        /opt/csw # Blastwave
        /opt
        ${SDL2_PATH}
        )

# Re-use the previous path:
FIND_PATH (CRYPTOPP_INCLUDE_DIR
  NAMES cryptopp/cryptlib.h
  HINTS ${CRYPTOPP_ROOT_DIR}
  PATH_SUFFIXES include
  PATHS ${CRYPTOPP_SEARCH_PATHS}
  DOC "CryptoPP include directory")

FIND_LIBRARY (CRYPTOPP_LIBRARY
  NAMES cryptlib cryptopp cryptopp-static
  HINTS ${CRYPTOPP_ROOT_DIR}
  PATH_SUFFIXES lib
  PATHS ${CRYPTOPP_SEARCH_PATHS}
  DOC "CryptoPP release library")

SET (CRYPTOPP_LIBRARIES ${CRYPTOPP_LIBRARY})