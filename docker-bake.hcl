variable "IMAGE" {
  default = "docker.io/pgilad/pocket-shield"
}

variable "TAG" {
  default = formatdate("YYYY.MM.DD.hhmmss", timestamp())
}

variable "REVISION" {
  default = ""
}

group "default" {
  targets = ["release"]
}

target "release" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = [
    "${IMAGE}:${TAG}",
    "${IMAGE}:latest",
  ]

  attest = [
    "type=provenance,mode=max,version=v1",
    "type=sbom",
  ]

  labels = {
    "org.opencontainers.image.source"   = "https://github.com/pgilad/pocket-shield"
    "org.opencontainers.image.created"  = timestamp()
    "org.opencontainers.image.revision" = REVISION
  }
}
