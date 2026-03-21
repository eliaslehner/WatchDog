resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
  password       = "terraform_db_password_123"
  publicly_accessible = true
  encrypted = false
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
