ifs_trailer = NewIFShellScreen {
    nologo = 1,
    bNohelptext_accept = 1,
    bNohelptext_back = 1,
    bNohelptext_backPC = 1,
    music = "STOP",





    Enter = function(this, bFwd)
        gIFShellScreenTemplate_fnEnter(this, bFwd)
        gMovieAlwaysPlay = 1
        ScriptCB_CloseMovie()
        ScriptCB_EnableCursor(nil)
        local movies = { english = "movies\\trailer.mvs", french = "movies\\trailerfr.mvs", german = "movies\\trailergr.mvs" }
        local movie = movies[gLangStr] or movies.english
        ScriptCB_OpenMovie(movie, "")
        ifelem_shellscreen_fnStartMovie("trailer", 0, nil, 1)
        if ScriptCB_IsMoviePlaying() then
            ScriptCB_SetShellMusic()
            ScriptCB_SndBusFade("shellfx", 0, 0)
            StopAudioStream(gVoiceOverStream, 0)
            StopAudioStream(gMusicStream, 0)
        end
    end,








    Exit = function(this, bFwd)
        ScriptCB_StopMovie()
        ScriptCB_CloseMovie()
        ScriptCB_SndBusFade("shellfx", 0, 1)
        ScriptCB_OpenMovie(gMovieStream, "")
        gMovieAlwaysPlay = nil
    end,


    Update = function(this, fDt)
        if not ScriptCB_IsMoviePlaying() then
            ScriptCB_PopScreen()
        else
            ScriptCB_EnableCursor(nil)
        end
    end,

    Input_Accept = function(this)
        ifelem_shellscreen_fnStopMovie()
    end,

    Input_Start = function(this)
        if gPlatformStr == "PC" then
            ifelem_shellscreen_fnStopMovie()
        end
    end,

    Input_Back = function(this)
        ifelem_shellscreen_fnStopMovie()
    end,



    Input_GeneralUp = function(this) end,

    Input_GeneralRight = function(this) end,

    Input_GeneralDown = function(this) end,

    Input_GeneralLeft = function(this) end,

    Input_GeneralUp2 = function(this) end,

    Input_GeneralRight2 = function(this) end,

    Input_GeneralDown2 = function(this) end,

    Input_GeneralLeft2 = function(this) end,
}
AddIFScreen(ifs_trailer, "ifs_trailer")
