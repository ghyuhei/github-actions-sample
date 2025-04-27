variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "public_subnet_01_cidr" {
  default = "10.0.0.0/24"
}

variable "public_subnet_02_cidr" {
  default = "10.0.1.0/24"
}

variable "private_subnet_01_cidr" {
  default = "10.0.2.0/24"
}

variable "private_subnet_02_cidr" {
  default = "10.0.3.0/24"
}

provider "aws" {
  region  = "ap-northeast-1"
  profile = "xxxx" #変更してください SSO profile名
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "github-actions-push-test"
  }
}

resource "aws_subnet" "public_01" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_01_cidr
  availability_zone       = "ap-northeast-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "github-actions-push-test-public-01"
  }
}

resource "aws_subnet" "public_02" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_02_cidr
  availability_zone       = "ap-northeast-1c"
  map_public_ip_on_launch = true

  tags = {
    Name = "github-actions-push-test-public-02"
  }
}

resource "aws_subnet" "private_01" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_01_cidr
  availability_zone = "ap-northeast-1a"

  tags = {
    Name = "github-actions-push-test-private-01"
  }
}

resource "aws_subnet" "private_02" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_02_cidr
  availability_zone = "ap-northeast-1c"

  tags = {
    Name = "github-actions-push-test-private-02"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "github-actions-push-test-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "github-actions-push-test-public-rtb"
  }
}

resource "aws_route" "default_route" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

resource "aws_route_table_association" "public_01" {
  subnet_id      = aws_subnet.public_01.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_02" {
  subnet_id      = aws_subnet.public_02.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "github-actions-push-test-private-rtb"
  }
}

resource "aws_route_table_association" "private_01" {
  subnet_id      = aws_subnet.private_01.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_02" {
  subnet_id      = aws_subnet.private_02.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "alb" {
  name        = "github-actions-push-test-sg-alb"
  description = "for alb"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "ALL"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "github-actions-push-test-sg-alb"
  }
}

resource "aws_security_group" "ecs" {
  name        = "github-actions-push-test-sg-ecs"
  description = "for ecs"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "ALL"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "github-actions-push-test-sg-ecs"
  }
}

resource "aws_security_group" "vpc_endpoint" {
  name        = "github-actions-push-test-vpc-endpoint-sg"
  description = "for VPC Endpoint"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "github-actions-push-test-vpc-endpoint-sg"
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.ap-northeast-1.s3"
  route_table_ids   = [aws_route_table.private.id]
  vpc_endpoint_type = "Gateway"
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.ap-northeast-1.ecr.dkr"
  subnet_ids          = [aws_subnet.private_01.id, aws_subnet.private_02.id]
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.ap-northeast-1.ecr.api"
  subnet_ids          = [aws_subnet.private_01.id, aws_subnet.private_02.id]
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.ap-northeast-1.logs"
  subnet_ids          = [aws_subnet.private_01.id, aws_subnet.private_02.id]
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.ap-northeast-1.ssmmessages"
  subnet_ids          = [aws_subnet.private_01.id, aws_subnet.private_02.id]
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
}

resource "aws_lb" "alb" {
  name               = "github-actions-push-test-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_01.id, aws_subnet.public_02.id]

  tags = {
    Name = "github-actions-push-test-alb"
  }
}

resource "aws_lb_target_group" "main" {
  name     = "github-actions-push-test-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    port                = "80"
    protocol            = "HTTP"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
    matcher             = "200"
  }

  target_type = "ip"
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}
/*
resource "aws_ecr_repository" "main" {
  name = "github-actions-push-test-ecr"

  force_delete = true
  encryption_configuration {
    encryption_type = "AES256"
  }
}
*/

resource "aws_cloudwatch_log_group" "ecs" {
  name = "/ecs/logs/github-actions-push-test-log"
}

resource "aws_iam_role" "task" {
  name = "github-actions-push-test-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "task" {
  name        = "github-actions-push-test-task-role-policy"
  description = "Allow ECS Exec"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.task.arn
}

resource "aws_iam_role" "task_execution" {
  name = "github-actions-push-test-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "task_execution" {
  name        = "github-actions-push-test-task-execution-role-policy"
  description = "Allow ECS Exec"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      Resource = "*"
    }]
  })
}
resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = aws_iam_policy.task_execution.arn
}

resource "aws_ecs_cluster" "main" {
  name = "github-actions-push-test-cluster"
}

resource "aws_ecs_task_definition" "main" {
  family                   = "github-actions-push-test-task-def"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name  = "github-actions-push-test-task",
      image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.ap-northeast-1.amazonaws.com/github-actions-push-test-ecr:latest",
      portMappings = [{
        containerPort = 80,
        hostPort      = 80
      }],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name,
          awslogs-region        = "ap-northeast-1",
          awslogs-stream-prefix = "github-actions-push-test-log"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "main" {
  name                   = "github-actions-push-test-service"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.main.arn
  desired_count          = 1
  launch_type            = "FARGATE"
  enable_execute_command = true

  network_configuration {
    subnets          = [aws_subnet.private_01.id, aws_subnet.private_02.id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = "github-actions-push-test-task"
    container_port   = 80
  }

  depends_on = [aws_lb_listener.http]
}

data "aws_caller_identity" "current" {}
