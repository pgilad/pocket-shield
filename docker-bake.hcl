group "default" {
  targets = ["release"]
}

function "calver_tag" {
  params = [ts]
  result = formatdate("YYYY.MM.DD.hhmmss", ts)
}

target "release" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = [
    format("pgilad/pocket-shield:%s", calver_tag(timestamp()))
  ]

  attest = [
    "type=provenance,mode=max,version=v1",
    "type=sbom",
  ]

  labels = {
     "org.opencontainers.image.source" = "https://codeberg.org/pgilad/pocket-shield"
     "org.opencontainers.image.created" = timestamp()
   }

  output = ["type=registry"]
}
