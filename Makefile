PROJECT_NAME := Pulumi Amazon Web Services (AWS) EKS Components

VERSION         := $(shell pulumictl get version)
TESTPARALLELISM := 12

WORKING_DIR     := $(shell pwd)

build:: build_nodejs build_python build_dotnet

schema::
	cd provider/cmd/pulumi-gen-eks && go run main.go schema ../pulumi-resource-eks

build_nodejs:: VERSION := $(shell pulumictl get version --language javascript)
build_nodejs::
	rm -rf nodejs/eks/bin
	cd nodejs/eks && \
		yarn install && \
		yarn run tsc && \
		sed -e 's/\$${VERSION}/$(VERSION)/g' < package.json > bin/package.json && \
		cp ../../README.md ../../LICENSE bin/ && \
		cp -R dashboard bin/ && \
		cp -R cni bin/

build_python:: PYPI_VERSION := $(shell pulumictl get version --language python)
build_python:: schema
	rm -rf python
	cd provider/cmd/pulumi-gen-eks && go run main.go python ../../../python ../pulumi-resource-eks/schema.json $(VERSION)
	cd python/ && \
		cp ../README.md . && \
		python3 setup.py clean --all 2>/dev/null && \
		rm -rf ./bin/ ../python.bin/ && cp -R . ../python.bin && mv ../python.bin ./bin && \
		sed -i.bak -e "s/\$${VERSION}/$(PYPI_VERSION)/g" -e "s/\$${PLUGIN_VERSION}/$(VERSION)/g" ./bin/setup.py && \
		rm ./bin/setup.py.bak && \
		cd ./bin && python3 setup.py build sdist

build_dotnet:: DOTNET_VERSION := $(shell pulumictl get version --language dotnet)
build_dotnet:: schema
	rm -rf dotnet
	cd provider/cmd/pulumi-gen-eks && go run main.go dotnet ../../../dotnet ../pulumi-resource-eks/schema.json $(VERSION)
	cd dotnet/ && \
		echo "${DOTNET_VERSION}" >version.txt && \
        dotnet build /p:Version=${DOTNET_VERSION}

lint:
	cd nodejs/eks && \
		yarn install && \
		yarn run tslint -c ../tslint.json -p tsconfig.json

lint_provider::
	cd provider && golangci-lint run -c ../.golangci.yml

install_provider:: install_nodejs_sdk
	cd provider/cmd/pulumi-resource-eks	&& \
		rm -rf ./bin/ ../provider.bin/ && cp -R . ../provider.bin && mv ../provider.bin ./bin && \
		sed -e 's/\$${VERSION}/latest/g' < package.json > bin/package.json && \
		cd ./bin && \
			yarn install && \
			yarn link @pulumi/eks

install_nodejs_sdk:: build_nodejs
	cd $(WORKING_DIR)/nodejs/eks/bin && \
		yarn install && \
		yarn unlink && \
		yarn link

install_dotnet_sdk:: build_dotnet
	mkdir -p $(WORKING_DIR)/nuget
	find . -name '*.nupkg' -print -exec cp -p {} ${WORKING_DIR}/nuget \;

test_nodejs::
	cd examples && go test -v -count=1 -cover -timeout 2h -parallel ${TESTPARALLELISM} .

dev:: lint build_nodejs
test:: install_nodejs_sdk test_nodejs
