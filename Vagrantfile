# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.network "forwarded_port", guest: 8200, host: 8200, host_ip: "127.0.0.1"
  config.vm.network "public_network"

  config.vm.synced_folder "build", "/opt/plugins"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y unzip
    curl -Lso /tmp/vault.zip https://releases.hashicorp.com/vault/0.10.4/vault_0.10.4_linux_amd64.zip
    unzip -o /tmp/vault.zip -d /opt
  SHELL
end
