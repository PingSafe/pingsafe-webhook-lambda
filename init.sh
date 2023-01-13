!#/bin/bash

POSITIONAL_ARGS=()

usage() {
	echo ""
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--profile)
      PROFILE="$2"
      if [ -z $PROFILE ]
      then
      	PROFILE=default
      fi
      shift # past argument
      shift # past value
      ;;
    -r|--region)
      REGION="$2"
      shift # past argument
      shift # past value
      ;;
    -q|--queue-name)
      QUEUE_NAME="$2"
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option $1"
      usage()
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters


# create queue

# create lambda role and sqs queue permission

# create lambda

# upload source