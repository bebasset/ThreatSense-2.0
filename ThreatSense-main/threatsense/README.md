HOW TO RUN THREATSENSE

git clone https://github.com/bebasset/ThreatSense.git

cd ThreatSense

cp threatsense/.env.example threatsense/.env

-- then edit threatsense/.env as needed

docker compose -f threatsense/docker-compose.yml up -d --build
