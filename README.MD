# Projeto-Redes
Projeto de redes 2020/21
-----

### Comandos Sigma
file transfer -> scp -r -C ../Projeto-Redes/ ist1XXXX@sigma.tecnico.ulisboa.pt:~
login -> ssh ist1XXXX@sigma02.tecnico.ulisboa.pt
PD -> ./pd 193.136.128.104 -n tejo.tecnico.ulisboa.pt -p 58011

### Dúvidas
- Q: ~~NOS PODEMOS TER OS DIFERENTES FICHEIROS DIVIDIDOS EM PASTAS?~~
  R: Sim podemos
- Q: Temos duas instancias diferentes do mesmo User. Se uma fizer login a outra tb o tem de fazer?
  R: Não sabe, espero resposta
- Q: ~~login invalido devolver erro? e se for com uma password de tamanho errado? ~
  R: Se a password tiver menos de 8 caracteres mandar ERR. Se tiver 8 caracteres mas estiver errada para aquele UID devolver NOK
- Q: No AS, quando o utilizador tenta fazer uma ação sem ter feito login mandamos sempre o erro ELOG ou só se tentar fazer REQ?
- Q: Deixamos o utilizador fazer login depois de já ter feito login?
- Q: Como eq o userID pode estar errado no comando REQ se fizemos login antes e o user não consegue enviar o UID no comando?
- Q: Apenas devemos devolver EPD se não obtiveremos comunicação com o PD ou em todos os casos de erro durante o processo de comunicação com o PD?
- Q: O TID é gerado aleatóriamente? E pode ser repetido para diferentes users? Ou para o mesmo user?
- Q: Se tivermos duas instancias do User a autenticarem-se, o que devemos fazer?

### ToDos
Gastão:
- 

Pedro:
> PD:
- ~~Validação das mensagens recebidas pelo AS~~
- ~~Tratamento do sinal SIGINT~~
- ~~Escrever mensagens que o as manda para o pd, via user (quando o user e o as estiverem feitos)~~

> AS:
> - ~~permitir q PDs se registem outra vez qd mandam a password certa~~
- ~~criar um socket TCP~~
- ~~Implementar select~~
- ~~Implementar Request command~~
- ~~Implementar o comando authenticate~~
- ~~Fazer a comunicação com o User~~
- Fazer a comunicação com o FS
- IMPEDIR PROCESSOS ZOMBIE
- Ativar a flag verbose

Vicente:
- teste

### Primeira Reunião (Divisão):
- AS    (Pedro)
- PD    (Pedro)
- User  (Gastão)
- FS    (Vicente)

### Comando para aceder ao AS dos profs
- $ nc -u tejo.tecnico.ulisboa.pt 58011 (UDP)
- $ nc -t tejo.tecnico.ulisboa.pt 58011 (TCP)
  
### Comandos Makefile
- $ make -> compila o todos os ficheiros
- $ make clean -> apaga todos os executaveis da diretoria

### Alguns comandos utéis para o Git
git clone [url]
--------------
para clonar um repositorio git

git init
--------------
cria um novo repositorio git

git add [file]
-------------- 
para adicionar um novo arquivo (que ficara na lista de mudancas a fazer no proximo commit)

git add *
-------------
faz com que todos ficheiros novos sejam adicionados

git commit -m "comentario"
-------------- 
para implementar a mudança no repositorio, a flag -m permite um comentario

git diff
--------------
para ver as diferenças

git status
--------------
para ver status do que ira acontecer no proximo commit

git rm [file]
--------------
remove arquivo

git log
--------------
lista historico de versoes para o branch atual

git show [commit]
--------------
mostra as mudancas de conteudos do commit

git branch
--------------
lista as branches do repositorio atual

git branch [branch name]
--------------
cria novo branch

git branch -d [branch name]
--------------
remove um branch

git pull
--------------
adiciona as mudancas feitas no repositorio

git push
--------------
actualiza o repositorio com seus ultimos commits para outros usuarios  
