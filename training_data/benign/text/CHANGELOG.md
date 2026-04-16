# Changelog

## [2.0.0] - 2026-04-10
### Added
- ONNX-based anomaly detection model (v2)
- File-type-aware scoring with per-category thresholds
- LLM explanation integration via Ollama/Llama3
- Scan result caching with SQLite persistence
- Producer-consumer multi-threaded scan pipeline

### Changed
- Replaced synthetic training data with real-world benign samples
- Improved SHA-256 hashing with memory-mapped I/O for large files
- Redesigned detail panel with score hero visualization

### Fixed
- False positives on media files (PNG, PDF, DOCX)
- Memory leak in QNetworkAccessManager CVE lookup
- Race condition in scan timer during rapid cancel/restart

## [1.0.0] - 2026-03-01
### Added
- Initial release with basic file scanning
- SHA-256 hash-based malware detection
- Qt6 desktop UI with threat table
- NVD CVE lookup integration
