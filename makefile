FIXEDAPP_IMAGE=fixedapp-image
VULNAPP_IMAGE=vulnapp-image

FIXEDAPP_CONTAINER=fixedapp-container
VULNAPP_CONTAINER=vulnapp-container

all: clean_containers build run info

clean_containers:
	-docker stop $(FIXEDAPP_CONTAINER) $(VULNAPP_CONTAINER)
	-docker rm $(FIXEDAPP_CONTAINER) $(VULNAPP_CONTAINER)


build:
	docker build -t $(FIXEDAPP_IMAGE) -f fixedapp/Dockerfile .
	docker build -t $(VULNAPP_IMAGE) -f vulnapp/Dockerfile .


run:
	docker run -d --name $(VULNAPP_CONTAINER) -p 8000:5000 -e DATABASE_URL="postgresql://postgres:1234@host.docker.internal:5432/postgres" $(VULNAPP_IMAGE)
	docker run -d --name $(FIXEDAPP_CONTAINER) -p 8001:5001 -e DATABASE_URL="postgresql://postgres:1234@host.docker.internal:5432/postgres" $(FIXEDAPP_IMAGE)


info:
	@echo "VulnerableApp: http://localhost:8000"
	@echo "FixedApp: http://localhost:8001"

clean:
	-docker stop $(FIXEDAPP_CONTAINER) $(VULNAPP_CONTAINER)
	-docker rm $(FIXEDAPP_CONTAINER) $(VULNAPP_CONTAINER)
	-docker rmi $(FIXEDAPP_IMAGE) $(VULNAPP_IMAGE)

.PHONY: all build run clean info clean_containers
