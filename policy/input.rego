package policy

deny[msg] {
  input.resource_type == "aws_s3_bucket"
  input.acl == "public-read"
  msg := "S3 bucket must not be publicly readable"
}

deny[msg] {
  input.resource_type == "aws_s3_bucket"
  input.acl == "public-read-write"
  msg := "S3 bucket must not be publicly readable and writable"
}
