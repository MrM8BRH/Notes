```
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
docker system prune --all
docker compose pull
docker compose up -d
docker compose up -d --force-recreate
docker exec -it container-name sh
```
### services
To view list of all the services running in swarm

```
docker service ls 
```
To see all running services
```
docker stack services stack_name
```
to see all services logs
```
docker service logs stack_name service_name 
```
To scale services quickly across qualified node
```
docker service scale stack_name_service_name=replicas
```
### clean up
To clean or prune unused (dangling) images
```
docker image prune 
```
To remove all images which are not in use containers , add - a
```
docker image prune -a 
```
To prune your entire system
```
docker system prune 
```
To leave swarm
```
docker swarm leave  
```
To remove swarm ( deletes all volume data and database info)
```
docker stack rm stack_name  
```
To kill all running containers
```
docker kill $(docker ps -q ) 
```
