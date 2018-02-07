define sniffer
from Sniffer.Application import Application

Application().main()
endef
export sniffer

.PHONY: help run install

.DEFAULT_GOAL=help

help: ## Show help comments for the targets
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-10s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

install: ## Install the application
	virtualenv --no-site-packages --distribute .env && source .env/bin/activate && pip install -r requirements.txt

run: ## Run the application
	venv/bin/python -c "$$sniffer"