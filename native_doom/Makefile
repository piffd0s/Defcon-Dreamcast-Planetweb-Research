# Build the staged native Dreamcast DOOM (doom.bin) with gcc-sh-elf (no KOS).
# Requires: sudo apt install gcc-sh-elf   (provides sh-elf-gcc/as/ld + newlib)
CC      = sh-elf-gcc
OBJCOPY = sh-elf-objcopy
DG      = doomgeneric/doomgeneric
CFLAGS  = -m4-single-only -ml -O2 -ffreestanding -fno-builtin -fomit-frame-pointer \
          -DDOOMGENERIC_RESX=320 -DDOOMGENERIC_RESY=200 -DNORMALUNIX -DLINUX \
          -I$(DG) -Wno-implicit-function-declaration
LDFLAGS = -T dc.ld -nostartfiles -Wl,-Map=doom.map
DGSRC   = $(DG)/dummy.c $(DG)/am_map.c $(DG)/doomdef.c $(DG)/doomstat.c $(DG)/dstrings.c $(DG)/d_event.c $(DG)/d_items.c $(DG)/d_iwad.c $(DG)/d_loop.c $(DG)/d_main.c $(DG)/d_mode.c $(DG)/d_net.c $(DG)/f_finale.c $(DG)/f_wipe.c $(DG)/g_game.c $(DG)/hu_lib.c $(DG)/hu_stuff.c $(DG)/info.c $(DG)/i_cdmus.c $(DG)/i_endoom.c $(DG)/i_joystick.c $(DG)/i_scale.c $(DG)/i_sound.c $(DG)/i_system.c $(DG)/i_timer.c $(DG)/memio.c $(DG)/m_argv.c $(DG)/m_bbox.c $(DG)/m_cheat.c $(DG)/m_config.c $(DG)/m_controls.c $(DG)/m_fixed.c $(DG)/m_menu.c $(DG)/m_misc.c $(DG)/m_random.c $(DG)/p_ceilng.c $(DG)/p_doors.c $(DG)/p_enemy.c $(DG)/p_floor.c $(DG)/p_inter.c $(DG)/p_lights.c $(DG)/p_map.c $(DG)/p_maputl.c $(DG)/p_mobj.c $(DG)/p_plats.c $(DG)/p_pspr.c $(DG)/p_saveg.c $(DG)/p_setup.c $(DG)/p_sight.c $(DG)/p_spec.c $(DG)/p_switch.c $(DG)/p_telept.c $(DG)/p_tick.c $(DG)/p_user.c $(DG)/r_bsp.c $(DG)/r_data.c $(DG)/r_draw.c $(DG)/r_main.c $(DG)/r_plane.c $(DG)/r_segs.c $(DG)/r_sky.c $(DG)/r_things.c $(DG)/sha1.c $(DG)/sounds.c $(DG)/statdump.c $(DG)/st_lib.c $(DG)/st_stuff.c $(DG)/s_sound.c $(DG)/tables.c $(DG)/v_video.c $(DG)/wi_stuff.c $(DG)/w_checksum.c $(DG)/w_file.c $(DG)/w_main.c $(DG)/w_wad.c $(DG)/z_zone.c $(DG)/w_file_stdc.c $(DG)/i_input.c $(DG)/i_video.c $(DG)/doomgeneric.c $(DG)/mus2mid.c
OBJS    = startup.o doomgeneric_dc.o dc_syscalls.o $(DGSRC:.c=.o)

all: doom.bin
%.o: %.c ; $(CC) $(CFLAGS) -c $< -o $@
%.o: %.s ; $(CC) -ml -m4-single-only -c $< -o $@
doom.elf: $(OBJS) ; $(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -lc -lm -lgcc -o $@
doom.bin: doom.elf ; $(OBJCOPY) -O binary $< $@
clean: ; rm -f $(OBJS) doom.elf doom.bin doom.map
