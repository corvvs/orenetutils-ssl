command=${1}

echo "[[ ${command} ]]"
set -x

echo "42 is nice" | ./ft_ssl ${command}

echo "42 is nice" | ./ft_ssl ${command} -p

echo "Pity the living." | ./ft_ssl ${command} -q -r

echo "And above all," > file

./ft_ssl ${command} file

./ft_ssl ${command} -r file

./ft_ssl ${command} -s "pity those that aren't following baerista on spotify."

echo "be sure to handle edge cases carefully" | ./ft_ssl ${command} -p file

echo "some of this will not make sense at first" | ./ft_ssl ${command} file

echo "but eventually you will understand" | ./ft_ssl ${command} -p -r file

echo "GL HF let's go" | ./ft_ssl ${command} -p -s "foo" file

echo "one more thing" | ./ft_ssl ${command} -r -p -s "foo" file -s "bar"

echo "just to be extra clear" | ./ft_ssl ${command} -r -q -p -s "foo" file

set +x

echo