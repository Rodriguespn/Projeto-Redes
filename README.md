# Projeto-Redes
Projeto de redes 2020/21
-----

### Dúvidas
~~Os pedidos feito pelo utilizador na linha de comandos são comm letra minúscula e os enviados para o server com letra maiúscula? (com letra minuscula)~~

### ToDos
Gastão:
- 

Pedro:
- Validação do comando do stdin
- Mensagem de erro
- Encapsulamento das ações da função main
- Tratamento do sinal SIGINT

Vicente:
- 

### Primeira Reunião (Divisão):
- AS    (Pedro)
- PD    (Pedro)
- User  (Gastão)
- FS    (Vicente)

### Comando para aceder ao AS dos profs
- $ nc -u tejo.tecnico.ulisboa.pt 58011 (UDP)
- $ nc -t tejo.tecnico.ulisboa.pt 58011 (TCP)
  
### Comandos Makefile
- $ make AS -> compila o ficheiro as.c
- $ make FS -> compila o ficheiro fs.c
- $ make User -> compila o ficheiro user.c
- $ make PD -> compila o ficheiro pd.c
- $ make all -> compila o todos os ficheiros
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
