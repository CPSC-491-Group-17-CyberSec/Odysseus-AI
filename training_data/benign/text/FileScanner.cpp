// FileScanner.cpp
// MOC anchor: including the header here ensures CMake AUTOMOC generates
// moc_FileScanner.cpp (vtable + staticMetaObject for Q_OBJECT classes).
// All actual implementations live in the focused translation units below:
//
//   FileScannerContext.cpp   – OS/FS detection, filter-list construction, constructor
//   FileScannerDetectors.cpp – Name/extension, location, magic-byte checks         (-O2)
//   FileScannerHash.cpp      – SHA-256 hash DB loading and hash-based detection     (-O3)
//   FileScannerEngine.cpp    – doScan() main loop + FileScanner controller          (-O2)

#include "FileScanner.h"
