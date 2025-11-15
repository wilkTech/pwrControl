# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- WebSocket support for real-time dashboard updates
- API documentation (Swagger/OpenAPI)
- Docker support with docker-compose

### Fixed
- GPIO initialization on system startup
- Email notification delays
- Proxmox connection timeout handling

### Changed
- Improved logging with structured format
- Enhanced error messages with troubleshooting hints

## [1.0.0] - 2025-11-15

### Added
- Core infrastructure management system
- GPIO relay control
- Proxmox virtual machine monitoring
- Web-based dashboard interface
- Email notification system
- Heartbeat monitoring
- Configuration management with YAML
- Comprehensive logging system
- Host availability monitoring
- Systemd service integration

### Features
- Real-time relay status display
- Virtual machine management interface
- Host status overview
- Email alerts on status changes
- Graceful shutdown handling
- Thread pool for concurrent operations

### Security
- Configuration file protection with .gitignore
- Environment variable support for secrets
- SSL/TLS ready architecture

### Documentation
- README with quick start guide
- Installation guide for various platforms
- Deployment guide for production
- Configuration examples
- Contributing guidelines

## Version History

### Alpha (Pre-release)
- Initial project development
- Core functionality testing
- Community feedback integration

---

## Release Notes Format

### [Version] - YYYY-MM-DD

#### Added
- New features and capabilities

#### Changed
- Changes in existing functionality

#### Fixed
- Bug fixes

#### Removed
- Removed features

#### Security
- Security-related changes

#### Deprecated
- Soon-to-be removed features

---

## Upgrade Guide

### From alpha to 1.0.0
1. Backup your `config.yaml`
2. Pull latest changes: `git pull origin main`
3. Install dependencies: `pip install -r requirements.txt`
4. Restart service: `systemctl restart powercontrol`

### Breaking Changes
None for 1.0.0

---

## Planned Features (Roadmap)

- [ ] WebSocket real-time updates
- [ ] API authentication
- [ ] Multi-user support
- [ ] Advanced scheduling
- [ ] Machine learning anomaly detection
- [ ] Mobile app
- [ ] Database backend (PostgreSQL)
- [ ] Cluster support
- [ ] Performance metrics dashboard
- [ ] Backup automation

---

## Support

For issues and feature requests, visit:
https://github.com/yourusername/PowerControl/issues

For security vulnerabilities, contact: [security-email]
