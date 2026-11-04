#!/system/bin/sh
# Replaces init's built-in "init_user0" (= vdc --wait cryptfs init_user0 with
# reboot-into-recovery --prompt_and_wipe_data on failure). Same vold call,
# bounded to 60 s, result logged, no recovery reboot (that path would try to
# write the misc partition and would end the trial).
echo "<6>crownlte-romram: init_user0 begin (vdc --wait cryptfs init_user0, 60 s bound)" > /dev/kmsg
/system/bin/timeout 60 /system/bin/vdc --wait cryptfs init_user0 > /dev/crownlte/init_user0.out 2>&1
rc=$?
echo "<6>crownlte-romram: init_user0 end rc=$rc out=$(tr '\n' ' ' < /dev/crownlte/init_user0.out | cut -c1-300)" > /dev/kmsg
exit 0
