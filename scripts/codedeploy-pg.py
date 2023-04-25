import os

def main(path):
  dir_list = os.listdir(path)
  print(dir_list)
  
if __name__ == "__main__":
  main(sys.argv[1])
  
