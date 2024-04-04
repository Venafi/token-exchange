

gcloud compute ssh --zone "europe-west1-b" --project "jetstack-tim-ramlot" "token-exchange-experiment"

gcloud compute scp --zone "europe-west1-b" --project "jetstack-tim-ramlot" ./server "token-exchange-experiment:~/server"


sudo systemctl status token-exchange-experiment
sudo systemctl daemon-reload
sudo nano /etc/systemd/system/token-exchange-experiment.service
